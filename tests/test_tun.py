#!/usr/bin/env python3
"""Логика режима TUN без root. Сам хелпер под root проверяется в tests/tun/run.sh."""
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import dpi_core as core

HELPER = ROOT / "tun/byedpi-tg-tun"


class TunStatusTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.state = self.dir / "state"
        for pid, comm in ((41, "ciadpi"), (42, "hev-socks5-tunn")):
            (self.dir / "proc" / str(pid)).mkdir(parents=True)
            (self.dir / "proc" / str(pid) / "comm").write_text(comm + "\n")

    def status(self):
        return core.tun_status(self.state, self.dir / "proc")

    def test_no_state(self):
        self.assertFalse(self.status().running)

    def test_running(self):
        self.state.write_text("ciadpi_pid=41\nport=1080\nuid=999\nhev_pid=42\ndev=byedpi0\nipv6=0\nquic=block\n")
        self.assertEqual(self.status(), core.TunStatus(True, 1080, "byedpi0", "block", False))

    def test_half_started_is_not_running(self):
        self.state.write_text("ciadpi_pid=41\nport=1080\nuid=999\n")
        self.assertFalse(self.status().running)

    def test_pid_reused(self):
        self.state.write_text("ciadpi_pid=42\nport=1080\nhev_pid=41\n")
        self.assertFalse(self.status().running)

    def test_garbage(self):
        self.state.write_text("мусор")
        self.assertFalse(self.status().running)


class TunRunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bin = Path(self.tmp.name)
        self.log = self.bin / "log"
        env = mock.patch.dict(os.environ, {"PATH": f"{self.bin}:{os.environ['PATH']}", "SUDO_LOG": str(self.log)})
        env.start()
        self.addCleanup(env.stop)
        sudo = self.bin / "sudo"
        sudo.write_text('#!/bin/sh\nfor a; do printf "[%s]" "$a"; done > "$SUDO_LOG"\necho "Запущено"\n')
        sudo.chmod(sudo.stat().st_mode | stat.S_IEXEC)

    def test_start_passes_args_as_separate_words(self):
        args = core.tun_argv("-d1 -H:{sni} -At -s1", "google.com", True)
        self.assertEqual(core.tun_run("start", 1080, args, True), (0, "Запущено"))
        self.assertTrue(self.log.read_text().startswith(
            f"[-n][{core.TUN_HELPER}][start][1080][--allow-quic][--scope=all][--][-T"))
        self.assertTrue(self.log.read_text().endswith("[-d1][-H:google.com][-At][-s1]"))

    def test_no_ipv6_flag_in_tun(self):
        # с -X ciadpi отклоняет IPv6-адреса, а из туннеля приходят только адреса
        self.assertEqual(core.tun_argv("-X -d1", "g", True), ["-d1"])

    def test_scope_passed_and_validated(self):
        core.tun_run("start", 1080, ["-d1"], False, None, "only")
        self.assertIn("[1080][--scope=only][--][-d1]", self.log.read_text())
        core.tun_run("start", 1080, ["-d1"], False, None, "evil")
        self.assertIn("[--scope=all]", self.log.read_text())

    def test_stop(self):
        core.tun_run("stop")
        self.assertEqual(self.log.read_text(), f"[-n][{core.TUN_HELPER}][stop]")


class PickingTest(unittest.TestCase):
    def test_picking_allowed_only_when_user_traffic_bypasses_tunnel(self):
        self.assertFalse(core.tun_blocks_picking(core.TunStatus(False)))
        self.assertTrue(core.tun_blocks_picking(core.TunStatus(True, scope="all")))
        self.assertTrue(core.tun_blocks_picking(core.TunStatus(True, scope="except")))
        self.assertFalse(core.tun_blocks_picking(core.TunStatus(True, scope="only")))


DISCORD = """[Desktop Entry]
Name=Discord
Exec=/usr/bin/discord %U
Icon=discord
Type=Application
DBusActivatable=true

[Desktop Action new]
Name=Новое окно
Exec=/usr/bin/discord --new-window
"""


class DesktopAppsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        self.sys_apps = d / "usr/share/applications"
        self.sys_apps.mkdir(parents=True)
        (self.sys_apps / "discord.desktop").write_text(DISCORD)
        (self.sys_apps / "hidden.desktop").write_text("[Desktop Entry]\nName=H\nExec=h\nType=Application\nNoDisplay=true\n")
        (self.sys_apps / "org.mozilla.firefox.desktop").write_text("[Desktop Entry]\nName=Firefox\nExec=firefox %u\nType=Application\n")
        self.local = d / "home/applications"
        patches = [
            mock.patch.dict(os.environ, {"XDG_DATA_DIRS": str(d / "usr/share")}),
            mock.patch.object(core, "LOCAL_APPS", self.local),
            mock.patch.object(core, "DATA_HOME", d / "home"),
            mock.patch.object(core, "DESKTOP_BACKUP", d / "backup"),
            mock.patch.object(core, "RUN_WRAPPER", Path("/home/u/.local/bin/byedpi-tg-run")),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def apps(self):
        return {a.id: a for a in core.list_desktop_apps()}

    def test_list_skips_hidden(self):
        self.assertEqual(set(self.apps()), {"discord.desktop", "org.mozilla.firefox.desktop"})

    def test_wrap_every_exec_and_drop_dbus(self):
        core.wrap_app("discord.desktop")
        text = (self.local / "discord.desktop").read_text()
        self.assertIn("Exec=/home/u/.local/bin/byedpi-tg-run /usr/bin/discord %U", text)
        self.assertIn("Exec=/home/u/.local/bin/byedpi-tg-run /usr/bin/discord --new-window", text)
        self.assertNotIn("DBusActivatable", text)
        self.assertEqual(text.count(core.WRAP_KEY), 1)
        self.assertTrue(self.apps()["discord.desktop"].wrapped)
        self.assertEqual(core.wrapped_apps(), ["discord.desktop"])
        core.wrap_app("discord.desktop")       # повторно — без двойной обёртки
        self.assertEqual((self.local / "discord.desktop").read_text().count("byedpi-tg-run"), 2)

    def test_unwrap_restores_system_entry(self):
        core.wrap_app("discord.desktop")
        core.unwrap_app("discord.desktop")
        self.assertFalse((self.local / "discord.desktop").exists())
        self.assertFalse(self.apps()["discord.desktop"].wrapped)

    def test_users_own_entry_is_kept(self):
        self.local.mkdir(parents=True)
        own = "[Desktop Entry]\nName=Мой Firefox\nExec=firefox -P work\nType=Application\n"
        (self.local / "org.mozilla.firefox.desktop").write_text(own)
        core.wrap_app("org.mozilla.firefox.desktop")
        self.assertIn("byedpi-tg-run firefox -P work", (self.local / "org.mozilla.firefox.desktop").read_text())
        core.unwrap_app("org.mozilla.firefox.desktop")
        self.assertEqual((self.local / "org.mozilla.firefox.desktop").read_text(), own)

    def test_unwrap_leaves_foreign_entry(self):
        self.local.mkdir(parents=True)
        (self.local / "x.desktop").write_text("[Desktop Entry]\nExec=x\n")
        core.unwrap_app("x.desktop")
        self.assertTrue((self.local / "x.desktop").exists())

    def test_wrapper_path_with_space_is_quoted(self):
        with mock.patch.object(core, "RUN_WRAPPER", Path('/home/a b/run')):
            self.assertEqual(core._exec_prefix(), '"/home/a b/run" ')


class TunHelperTest(unittest.TestCase):
    def valid(self, args: list[str]) -> bool:
        """Запускает функцию valid_args из хелпера в обычном sh, без root."""
        text = HELPER.read_text()
        funcs = text[text.index("die()"):text.index("\n", text.index("die()"))] + "\n"
        start = text.index("valid_args()")
        funcs += text[start:text.index("\n}\n", start) + 3]
        r = subprocess.run(["sh", "-c", funcs + 'valid_args "$@"', "sh", *args], capture_output=True)
        return r.returncode == 0

    def test_every_strategy_passes_helper_filter(self):
        bad = [a for a in core.load_strategies()
               if not self.valid(core.tun_argv(a, "google.com", True))]
        self.assertEqual(bad, [])

    def test_combo_passes_helper_filter(self):
        combo = core.build_combo({"youtube": "-d1 -At -s1", "discord": "-r1+s"}, fallback="-s1")
        self.assertTrue(self.valid(core.tun_argv(combo, "google.com", True)))

    def test_overrides_rejected(self):
        for args in (["-p", "1"], ["-i0.0.0.0"], ["--port=1"], ["-E"], ["--daemon"], ["-w/tmp/x"]):
            self.assertFalse(self.valid(["-d1", *args]), args)

    def test_no_eval_and_fixed_paths(self):
        text = HELPER.read_text()
        self.assertNotIn("eval ", text)
        self.assertRegex(text, re.compile(r"^PATH=/usr/sbin:/usr/bin:/sbin:/bin$", re.M))


if __name__ == "__main__":
    unittest.main()
