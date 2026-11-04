#!/usr/bin/env python3
"""Логика голосового режима без root. Сам хелпер проверяется в tests/vm/run.sh."""
import os
import re
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import dpi_core as core


class VoiceStatusTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.state = self.dir / "state"
        (self.dir / "proc" / "42").mkdir(parents=True)

    def status(self):
        return core.voice_status(self.state, self.dir / "proc")

    def test_no_state(self):
        self.assertFalse(self.status().running)

    def test_running(self):
        self.state.write_text("pid=42\niface=enp4s0\nprofile=quic6\n")
        (self.dir / "proc/42/comm").write_text("nfqws\n")
        self.assertEqual(self.status(), core.VoiceStatus(True, "enp4s0", "quic6"))

    def test_pid_reused_by_other_process(self):
        self.state.write_text("pid=42\niface=enp4s0\nprofile=quic6\n")
        (self.dir / "proc/42/comm").write_text("bash\n")
        self.assertFalse(self.status().running)

    def test_dead_process_and_garbage(self):
        self.state.write_text("pid=43\niface=e\nprofile=p\n")
        self.assertFalse(self.status().running)
        self.state.write_text("мусор")
        self.assertFalse(self.status().running)


class VoiceRunTest(unittest.TestCase):
    """Настоящий запуск подставной команды sudo: проверяем аргументы и stdin."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bin = Path(self.tmp.name)
        self.log = self.bin / "log"
        env = mock.patch.dict(os.environ, {"PATH": f"{self.bin}:{os.environ['PATH']}", "SUDO_LOG": str(self.log)})
        env.start()
        self.addCleanup(env.stop)

    def fake_sudo(self, body: str):
        path = self.bin / "sudo"
        path.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$SUDO_LOG"\ncat >> "$SUDO_LOG"\n' + body)
        path.chmod(path.stat().st_mode | stat.S_IEXEC)

    def test_password_needed(self):
        self.fake_sudo('echo "sudo: a password is required" >&2; exit 1\n')
        self.assertEqual(core.voice_run("start", "quic6")[0], core.VOICE_NEED_PASSWORD)
        self.assertIn(f"-n {core.VOICE_HELPER} start quic6", self.log.read_text())

    def test_password_only_in_stdin(self):
        self.fake_sudo('echo "Запущено"\n')
        self.assertEqual(core.voice_run("stop", None, "pa ss"), (0, "Запущено"))
        first, second = self.log.read_text().splitlines()
        self.assertEqual(first, f"-S -k -p  {core.VOICE_HELPER} stop")
        self.assertEqual(second, "pa ss")

    def test_wrong_password(self):
        self.fake_sudo('echo "sudo: 1 incorrect password attempt" >&2; exit 1\n')
        self.assertEqual(core.voice_run("stop", None, "x"), (1, "Неверный пароль."))

    def test_helper_error_shown(self):
        self.fake_sudo('echo "nfqws не запустился" >&2; exit 1\n')
        self.assertEqual(core.voice_run("start", "quic6"), (1, "nfqws не запустился"))

    def test_no_sudo(self):
        with mock.patch.dict(os.environ, {"PATH": str(self.bin)}):
            code, text = core.voice_run("stop")
        self.assertEqual(code, 1)
        self.assertIn("Нет sudo", text)


class VoiceFilesTest(unittest.TestCase):
    def test_profiles_match_helper(self):
        helper = (ROOT / "voice/byedpi-tg-voice").read_text()
        body = helper[helper.index("profile_args()"):helper.index("valid_iface()")]
        self.assertEqual(set(re.findall(r"^\s+(\w+)\) ARGS=", body, re.M)), set(core.VOICE_PROFILES))

    def test_default_profile_exists(self):
        self.assertIn(core.DEFAULT_CFG["voice_profile"], core.VOICE_PROFILES)

    def test_helper_fails_open_and_has_no_eval(self):
        helper = (ROOT / "voice/byedpi-tg-voice").read_text()
        self.assertIn("--queue-bypass", helper)
        self.assertNotIn("eval ", helper)


if __name__ == "__main__":
    unittest.main()
