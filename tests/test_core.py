#!/usr/bin/env python3
"""
Проверки логики подбора. Настоящий ciadpi работает против симулятора DPI на loopback:

  yt-sim.test  — пропускает, только если изменена минорная версия TLS-записи (-m3);
  dc-sim.test  — пропускает, только если SNI разорван границей TLS-записи;
  fr-sim.test  — пропускает всё, но замораживает ответ после 16 КБ.

Заблокированное соединение получает RST. Условия для YouTube и Discord взаимоисключающие,
поэтому пройти оба может только раздельная стратегия.

Запуск: python -m unittest discover -s tests -v   (нужен собранный ciadpi)
"""
import asyncio
import shlex
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import dpi_core as core

BIG = 200 * 1024
SIM_DOMAINS = {"youtube": ["yt-sim.test"], "discord": ["dc-sim.test"]}


def rst_close(writer):
    sock = writer.get_extra_info("socket")
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    writer.close()


def reassemble(data: bytes):
    """Разбирает TLS-записи. Возвращает (записи, весь ClientHello) или None, если данных мало."""
    records, whole, pos = [], b"", 0
    while pos + 5 <= len(data):
        if data[pos] != 0x16:
            return records or [b""], whole
        length = int.from_bytes(data[pos + 3:pos + 5], "big")
        if pos + 5 + length > len(data):
            return None
        records.append(data[pos + 5:pos + 5 + length])
        whole += records[-1]
        pos += 5 + length
        if len(whole) >= 4 and len(whole) >= int.from_bytes(whole[1:4], "big") + 4:
            return records, whole
    return None


class Simulator:
    def __init__(self, cert, key):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.ready.wait()

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._start())
        self.ready.set()
        self.loop.run_forever()

    async def _start(self):
        self.backend = await asyncio.start_server(self._http, "127.0.0.1", 0, ssl=self.ctx)
        self.backend_port = self.backend.sockets[0].getsockname()[1]
        self.front = await asyncio.start_server(self._dpi, "127.0.0.1", 0)
        self.port = self.front.sockets[0].getsockname()[1]

    async def _http(self, r, w):
        try:
            req = await r.readuntil(b"\r\n\r\n")
            path = req.split(b" ")[1]
            body = b"x" * BIG if path == b"/big" else b"small"
            w.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
            await w.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        finally:
            w.close()

    async def _dpi(self, r, w):
        data = await r.read(65536)
        hello = reassemble(data)
        while hello is None:
            more = await r.read(65536)
            if not more:
                return w.close()
            data += more
            hello = reassemble(data)
        records, whole = hello
        sni = next((n for n in (b"yt-sim.test", b"dc-sim.test", b"fr-sim.test") if n in whole), None)
        sni_cut_by_record = sni is not None and not any(sni in rec for rec in records)
        if sni == b"yt-sim.test":
            allowed = data[2] != 1      # у обычного ClientHello запись начинается с 0x0301
        elif sni == b"dc-sim.test":
            allowed = sni_cut_by_record
        else:
            allowed = True
        if not allowed:
            return rst_close(w)
        freeze = sni == b"fr-sim.test"
        br, bw = await asyncio.open_connection("127.0.0.1", self.backend_port)
        bw.write(data)
        await bw.drain()

        async def up():
            try:
                while chunk := await r.read(65536):
                    bw.write(chunk)
                    await bw.drain()
            except ConnectionError:
                pass

        async def down():
            sent = 0
            try:
                while chunk := await br.read(65536):
                    if freeze and sent + len(chunk) > 16 * 1024:
                        w.write(chunk[:16 * 1024 - sent])
                        await w.drain()
                        await asyncio.sleep(3600)
                    sent += len(chunk)
                    w.write(chunk)
                    await w.drain()
            except ConnectionError:
                pass
            finally:
                w.close()

        await asyncio.gather(up(), down(), return_exceptions=True)


class SimTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not core.CIADPI.exists():
            raise unittest.SkipTest(f"нет {core.CIADPI}")
        cls.tmp = tempfile.TemporaryDirectory()
        cert, key = Path(cls.tmp.name) / "c.pem", Path(cls.tmp.name) / "k.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=sim.test", "-keyout", key, "-out", cert],
                       check=True, capture_output=True)
        cls.sim = Simulator(cert, key)
        p = cls.sim.port
        extra = ["-k"]
        for host in ("yt-sim.test", "dc-sim.test", "fr-sim.test"):
            extra += ["--resolve", f"{host}:{p}:127.0.0.1"]
        cls.real_probe = core.probe
        core.probe = lambda t, port, timeout, fp="": core._probe_curl(t, port, timeout, extra)
        cls.real_domains = core.SERVICE_DOMAINS
        core.SERVICE_DOMAINS = SIM_DOMAINS
        cls.yt = [core.Target("youtube", "мало", f"https://yt-sim.test:{p}/small"),
                  core.Target("youtube", "много", f"https://yt-sim.test:{p}/big", 64 * 1024)]
        cls.dc = [core.Target("discord", "мало", f"https://dc-sim.test:{p}/small"),
                  core.Target("discord", "много", f"https://dc-sim.test:{p}/big", 64 * 1024)]
        cls.fr = core.Target("youtube", "заморозка", f"https://fr-sim.test:{p}/big", 64 * 1024)

    @classmethod
    def tearDownClass(cls):
        core.probe = cls.real_probe
        core.SERVICE_DOMAINS = cls.real_domains
        cls.tmp.cleanup()

    def score(self, args, targets=None, **kw):
        return core.evaluate_strategy(args, targets or self.yt + self.dc, "google.com", 4, True, "", **kw)

    def test_tlsminor_passes_only_youtube(self):
        r = self.score("-m3 -a1")
        self.assertEqual(r.scores, {"youtube": (2, 2), "discord": (0, 2)}, r.fails)

    def test_tlsrec_passes_only_discord(self):
        r = self.score("-r1+s -a1")
        self.assertEqual(r.scores, {"youtube": (0, 2), "discord": (2, 2)}, r.fails)

    def test_no_desync_is_blocked(self):
        r = self.score("-a1")
        self.assertEqual(r.scores, {"youtube": (0, 2), "discord": (0, 2)}, r.fails)

    def test_combo_passes_both(self):
        combo = core.build_combo({"youtube": "-m3 -a1", "discord": "-r1+s -a1"})
        r = self.score(combo)
        self.assertEqual(r.scores, {"youtube": (2, 2), "discord": (2, 2)}, (combo, r.fails))

    def test_fallback_group_keeps_host_filter(self):
        # запасная группа после -At тоже должна быть ограничена своими доменами
        combo = core.build_combo({"youtube": "-a1 -At -m3 -a1", "discord": "-r1+s -a1"})
        self.assertEqual(combo.count("yt-sim.test"), 2)
        r = self.score(combo)
        self.assertEqual(r.scores, {"youtube": (2, 2), "discord": (2, 2)}, (combo, r.fails))

    def test_pick_builds_and_verifies_combo(self):
        rows, best = core.pick_strategies(["-a1", "-m3 -a1", "-r1+s -a1"], self.yt + self.dc,
                                          "google.com", 4)
        self.assertEqual(best.kind, "combo", [(r.args, r.scores) for r in rows])
        self.assertEqual(best.scores, {"youtube": (2, 2), "discord": (2, 2)})

    def test_pick_prefers_single_strategy_when_enough(self):
        rows, best = core.pick_strategies(["-m3 -a1"], self.yt, "google.com", 4)
        self.assertEqual(best.args, "-m3 -a1")
        self.assertEqual(best.kind, "base")

    def test_freeze_is_not_success(self):
        p = core.probe(self.fr, None, 3)
        self.assertFalse(p.ok)
        self.assertEqual(p.reason, "freeze", p)

    def test_small_answer_fails_freeze_check(self):
        t = core.Target("youtube", "x", f"https://fr-sim.test:{self.sim.port}/small", 64 * 1024)
        p = core.probe(t, None, 3)
        self.assertEqual((p.ok, p.reason), (False, "short"), p)

    def test_invalid_args_score_zero(self):
        r = self.score("--no-such-option")
        self.assertEqual(r.total, 0)
        self.assertIn("не принял", r.fails[0])


class FingerprintTests(unittest.TestCase):
    """Браузерный отпечаток (curl_cffi) на заморозке и на обычном ответе."""

    @classmethod
    def setUpClass(cls):
        if core.cffi_requests is None:
            raise unittest.SkipTest("нет curl_cffi")
        cls.tmp = tempfile.TemporaryDirectory()
        cert, key = Path(cls.tmp.name) / "c.pem", Path(cls.tmp.name) / "k.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=sim.test", "-keyout", key, "-out", cert],
                       check=True, capture_output=True)
        cls.sim = Simulator(cert, key)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_big_answer_ok(self):
        t = core.Target("youtube", "x", f"https://127.0.0.1:{self.sim.backend_port}/big", 64 * 1024)
        p = core._probe_cffi(t, None, 4, "firefox", verify=False)
        self.assertTrue(p.ok, p)
        self.assertEqual(p.size, BIG)

    def test_small_answer_is_short(self):
        t = core.Target("youtube", "x", f"https://127.0.0.1:{self.sim.backend_port}/small", 64 * 1024)
        self.assertEqual(core._probe_cffi(t, None, 4, "firefox", verify=False).reason, "short")

    def test_range_is_respected_or_ignored_safely(self):
        t = core.Target("discord", "x", f"https://127.0.0.1:{self.sim.backend_port}/big", 64 * 1024, 128 * 1024)
        self.assertTrue(core._probe_cffi(t, None, 4, "firefox", verify=False).ok)

    def test_refused_port(self):
        t = core.Target("youtube", "x", f"https://127.0.0.1:{core.free_port()}/")
        self.assertEqual(core._probe_cffi(t, None, 2, "firefox", verify=False).reason, "connect")

    def test_stall_after_handshake_is_freeze(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(Path(self.tmp.name) / "c.pem", Path(self.tmp.name) / "k.pem")
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        held = []

        def accept():
            conn, _ = srv.accept()
            held.append(ctx.wrap_socket(conn, server_side=True))
        threading.Thread(target=accept, daemon=True).start()
        t = core.Target("youtube", "x", f"https://127.0.0.1:{port}/")
        p = core._probe_cffi(t, None, 2, "firefox", verify=False)
        srv.close()
        self.assertEqual(p.reason, "freeze", p)

    def test_silent_server_is_timeout(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        t = core.Target("youtube", "x", f"https://127.0.0.1:{srv.getsockname()[1]}/")
        p = core._probe_cffi(t, None, 2, "firefox", verify=False)
        srv.close()
        self.assertEqual(p.reason, "timeout", p)


class PureTests(unittest.TestCase):
    def test_every_strategy_is_accepted_by_ciadpi(self):
        if not core.CIADPI.exists():
            self.skipTest("нет ciadpi")
        bad = []
        for args in core.load_strategies():
            with core.running_ciadpi(args, "google.com") as port:
                if port is None:
                    bad.append(args)
        self.assertEqual(bad, [])

    def test_timeout_flag_only_with_t_trigger(self):
        def has_t(args):
            return any(f.startswith("-T") for f in core.runtime_flags(shlex.split(args)))
        self.assertTrue(has_t("-a1 -At,r,s -a1"))
        self.assertTrue(has_t("--auto=torst -a1"))
        self.assertTrue(has_t("-a1 -A t -a1"))
        self.assertFalse(has_t("-a1 -Ar,s -a1"))
        self.assertEqual([f for f in core.runtime_flags(shlex.split("-a1 -At -T5")) if f.startswith("-T")], [])

    def test_timeout_flag_matches_installed_ciadpi(self):
        if not core.CIADPI.exists():
            self.skipTest("нет ciadpi")
        core._timeout_flag.cache_clear()
        with core.running_ciadpi("-a1 -At -d1+s -a1", "google.com") as port:
            self.assertIsNotNone(port, f"ciadpi не принял {core._timeout_flag()}")

    def test_redirect_target_is_not_called_freeze(self):
        t = core.Target("discord", "x", "https://x/", redirects=True)
        self.assertEqual(core._judge(t, 0, 0, 8, 28, handshake=0.5).reason, "timeout")
        self.assertEqual(core._judge(t, 0, 100, 8, 28, handshake=0.5).reason, "freeze")

    def test_with_ttl(self):
        self.assertEqual(core.with_ttl("-f-1 -a1", 5), "-f-1 -t5 -a1")
        self.assertEqual(core.with_ttl("-f-1 -t8 -a1", 5), "-f-1 -t5 -a1")
        self.assertEqual(core.with_ttl("--fake -1 --ttl 8 --split 1+s", 4), "--fake -1 -t4 --split 1+s")
        self.assertEqual(core.with_ttl("-d1+s -f1+nm -t6 -a1 -As -f-1 -a1", 7),
                         "-d1+s -f1+nm -t7 -a1 -As -f-1 -t7 -a1")

    def test_has_fake(self):
        self.assertTrue(core.has_fake("-d1 -f-1 -a1"))
        self.assertTrue(core.has_fake("--fake -1 -a1"))
        self.assertFalse(core.has_fake("-d1+s -s5 -a1"))

    def test_expected_nets(self):
        self.assertTrue(core.in_nets("142.251.150.4", "google"))
        self.assertTrue(core.in_nets("162.159.136.232", "cloudflare"))
        self.assertFalse(core.in_nets("10.10.34.34", "google"))
        self.assertFalse(core.in_nets("8.8.8.8", "cloudflare"))

    def test_old_config_migrates(self):
        with tempfile.TemporaryDirectory() as d:
            real = core.CFG_FILE, core.CFG_DIR
            core.CFG_DIR = Path(d)
            core.CFG_FILE = Path(d) / "config.json"
            try:
                core.CFG_FILE.write_text('{"test_sites": ["a"], "test_timeout": 5, "tg_secret": "ab",'
                                         ' "browser_cmd": "%s", "favorites": [[1, 2, "-a1"]],'
                                         ' "byedpi_args": "-d1"}' % core.OLD_BROWSER_CMD)
                c = core.load_cfg()
            finally:
                core.CFG_FILE, core.CFG_DIR = real
        self.assertNotIn("test_sites", c)
        self.assertEqual(c["browser_cmd"], "")
        self.assertEqual(c["favorites"], [])
        self.assertEqual((c["byedpi_args"], c["tg_secret"]), ("-d1", "ab"))


if __name__ == "__main__":
    unittest.main()
