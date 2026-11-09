#!/usr/bin/env python3
"""Выводы контроля: когда подбор стратегий заведомо бесполезен."""
import socket
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import dpi_core as core


def probes(*results):
    out = []
    for t, r in zip(core.CONTROL_TARGETS, results):
        ok = r == "ok"
        out.append(core.Probe(t, ok, r, 200 if ok else 0, detail="" if ok else "подробности"))
    return out


class VerdictTest(unittest.TestCase):
    def verdicts(self, direct, proxy):
        res = core.ControlResult(probes(*direct), None if proxy is None else probes(*proxy))
        return [(fatal, text.split(":")[0].split(".")[0]) for fatal, text in res.verdicts()]

    def test_all_fine(self):
        self.assertEqual(self.verdicts(("ok", "ok", "ok"), ("ok", "ok", "ok")), [])

    def test_no_internet(self):
        v = self.verdicts(("dns", "dns", "dns"), ("dns", "dns", "dns"))
        self.assertEqual(len(v), 1)
        self.assertTrue(v[0][0])

    def test_whitelist(self):
        v = self.verdicts(("ok", "timeout", "timeout"), ("ok", "timeout", "timeout"))
        self.assertTrue(v[0][0])
        self.assertIn("белые списки", core.ControlResult(probes("ok", "timeout", "timeout"),
                                                        probes("ok", "ok", "ok")).verdicts()[0][1])

    def test_broken_proxy_path(self):
        v = self.verdicts(("ok", "ok", "ok"), ("error", "error", "error"))
        self.assertEqual([f for f, _ in v], [True])

    def test_ciadpi_missing(self):
        v = self.verdicts(("ok", "ok", "ok"), None)
        self.assertEqual([f for f, _ in v], [True])

    def test_cloudflare_freeze_is_only_a_warning(self):
        v = self.verdicts(("ok", "ok", "freeze"), ("ok", "ok", "freeze"))
        self.assertEqual([f for f, _ in v], [False])


class DetailTest(unittest.TestCase):
    def test_curl_error_text_kept(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        t = core.Target("control", "x", f"https://127.0.0.1:{port}/")
        p = core._probe_curl(t, None, 2)
        self.assertFalse(p.ok)
        self.assertEqual(p.reason, "connect")
        self.assertIn("127.0.0.1", p.detail)
        self.assertIn(p.detail, core._fmt_probe(p))


if __name__ == "__main__":
    unittest.main()
