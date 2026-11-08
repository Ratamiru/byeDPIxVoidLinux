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
            f"[-n][{core.TUN_HELPER}][start][1080][--allow-quic][--][-T"))
        self.assertTrue(self.log.read_text().endswith("[-d1][-H:google.com][-At][-s1]"))

    def test_no_ipv6_flag_in_tun(self):
        # с -X ciadpi отклоняет IPv6-адреса, а из туннеля приходят только адреса
        self.assertEqual(core.tun_argv("-X -d1", "g", True), ["-d1"])

    def test_stop(self):
        core.tun_run("stop")
        self.assertEqual(self.log.read_text(), f"[-n][{core.TUN_HELPER}][stop]")


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
