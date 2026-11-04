#!/usr/bin/env python3
"""
Логика ByeDPI × TG без GUI: конфиг, проверки сервисов, подбор стратегий,
сборка раздельных правил для YouTube и Discord, диагностика.

Запуск из консоли (удобно, когда VPN выключен и окно не нужно):
    byedpi-tg-diag            — отчёт о сети
    byedpi-tg-diag --pick     — плюс полный подбор стратегий
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import re
import secrets
import shlex
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable

try:
    from curl_cffi import CurlInfo
    from curl_cffi import requests as cffi_requests
except ImportError:      # старая установка: работаем через curl, но с его отпечатком TLS
    CurlInfo = None
    cffi_requests = None

# ─────────────────────────── пути и конфиг ───────────────────────────

HERE = Path(__file__).resolve().parent
APP_HOME = Path(os.environ.get("BYEDPI_TG_HOME", Path.home() / ".local/share/byedpi-tg"))
CFG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "byedpi-tg"
CFG_FILE = CFG_DIR / "config.json"
USER_STRATEGIES = CFG_DIR / "strategies.list"      # сюда кладёт «Обновить список»
REPORT_FILE = CFG_DIR / "diagnostic.txt"
PAC_FILE = CFG_DIR / "proxy.pac"
FIREFOX_PROFILE = CFG_DIR / "firefox-profile"

CIADPI = APP_HOME / "byedpi" / "ciadpi"
TGWS_DIR = APP_HOME / "tg-ws-proxy"
VENV_PY = APP_HOME / "venv" / "bin" / "python"

STRATEGIES_URL = ("https://raw.githubusercontent.com/romanvht/ByeByeDPI/master/"
                  "app/src/main/assets/proxytest_strategies.list")

DEFAULT_ARGS = ("-o1 -d1 -a1 -At,r,s -s1 -d1 -s5+s -s10+s -s15+s -s20+s -r1+s -S -a1 "
                "-As -s1 -d1 -s5+s -s10+s -s15+s -s20+s -S -a1")
OLD_BROWSER_CMD = "chromium --proxy-server=socks5://127.0.0.1:{port}"

DEFAULT_CFG = {
    "byedpi_port": 1080,
    "byedpi_args": DEFAULT_ARGS,
    "fake_sni": "google.com",
    "ipv4_only": True,           # -X: не уходить на сломанный IPv6 у провайдера
    "tg_port": 1443,
    "tg_secret": "",
    "tg_extra_args": "",
    "browser_cmd": "",           # пусто — найти браузер автоматически
    "discord_cmd": "",           # пусто — найти клиент Discord автоматически
    "voice_profile": "quic6",    # профиль nfqws для голоса Discord
    "probe_timeout": 8,
    "probe_fingerprint": "firefox",
    "custom_targets": [],        # [{"service": "discord", "url": "https://…", "min_bytes": 0}]
    "extra_proxy_domains": [],   # дополнительные домены для PAC
    "favorites": [],             # [{"args": "...", "scores": {"youtube": [5, 6], …}}]
    "autostart_byedpi": False,
    "autostart_tg": False,
    "start_hidden": False,
}


def load_cfg() -> dict:
    cfg = dict(DEFAULT_CFG)
    try:
        cfg.update(json.loads(CFG_FILE.read_text()))
    except (OSError, ValueError):
        pass
    # миграция конфига старой версии
    for old_key in ("test_sites", "test_timeout"):
        cfg.pop(old_key, None)
    if cfg.get("browser_cmd") == OLD_BROWSER_CMD:
        cfg["browser_cmd"] = ""
    cfg["favorites"] = [f for f in cfg.get("favorites", []) if isinstance(f, dict)]
    if not cfg["tg_secret"]:
        # секрет храним постоянно, чтобы прокси в Telegram не приходилось перенастраивать
        cfg["tg_secret"] = secrets.token_hex(16)
        save_cfg(cfg)
    return cfg


def save_cfg(cfg: dict) -> None:
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    CFG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))


# ─────────────────────────── сервисы и цели проверки ───────────────────────────

@dataclass(frozen=True)
class Target:
    service: str
    name: str
    url: str
    min_bytes: int = 0      # 0 — достаточно ответа сервера; иначе нужен объём, чтобы поймать заморозку
    range_bytes: int = 0    # запросить только первые N байт большого файла
    redirects: bool = False # идёт через редирект: рукопожатие могло пройти не с тем сервером


SERVICE_TITLES = {"youtube": "YouTube", "discord": "Discord"}
FREEZE_CHECK = 64 * 1024    # заметно больше порога заморозки ТСПУ (~16–20 КБ)

TARGETS = [
    Target("youtube", "главная", "https://www.youtube.com/", FREEZE_CHECK),
    Target("youtube", "превью", "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg", 16 * 1024 + 1),
    Target("youtube", "API плеера", "https://youtubei.googleapis.com/generate_204"),
    Target("youtube", "аватары", "https://yt3.ggpht.com/"),
    Target("youtube", "домен видео", "https://redirector.googlevideo.com/report_mapping", FREEZE_CHECK),
    Target("discord", "сайт", "https://discord.com/", FREEZE_CHECK),
    Target("discord", "API", "https://discord.com/api/v9/gateway"),
    Target("discord", "gateway", "https://gateway.discord.gg/"),
    Target("discord", "CDN", "https://cdn.discordapp.com/"),
    Target("discord", "медиа", "https://media.discordapp.net/"),
    Target("discord", "скачивание", "https://discord.com/api/download?platform=linux&format=tar.gz",
           FREEZE_CHECK, 128 * 1024, redirects=True),
]

# Домены для групп byedpi (-H) и PAC. Поддомены совпадают автоматически.
SERVICE_DOMAINS = {
    "youtube": ["youtube.com", "youtu.be", "yt.be", "youtube-nocookie.com", "ytimg.com",
                "ggpht.com", "googlevideo.com", "googleusercontent.com", "googleapis.com",
                "gstatic.com", "gvt1.com"],
    "discord": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media",
                "discordcdn.com", "discord.co", "discord.dev", "discord.gift", "discord.new",
                "discordstatus.com", "dis.gd"],
}


def all_targets(cfg: dict, video_node: str | None = None) -> list[Target]:
    targets = list(TARGETS)
    if video_node:
        targets.append(Target("youtube", "видеосервер", video_node))
    for t in cfg.get("custom_targets") or []:
        if t.get("service") in SERVICE_TITLES and t.get("url"):
            targets.append(Target(t["service"], t.get("name", t["url"]), t["url"],
                                  int(t.get("min_bytes", 0))))
    return targets


def discover_video_node(port: int | None = None) -> str | None:
    """Узнаёт реальный ближайший видеосервер Google, а не берёт случайный из списка."""
    cmd = ["curl", "-s", "-o", "/dev/null", "-m", "6", "-w", "%{redirect_url}",
           "https://redirector.gvt1.com/edgedl/chrome/dict/en-us-10-1.bdic"]
    if port:
        cmd[1:1] = ["-x", f"socks5h://127.0.0.1:{port}"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=9).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"//(rr\d+---sn-[a-z0-9-]+)\.", out)
    return f"https://{m.group(1)}.googlevideo.com/generate_204" if m else None


# ─────────────────────────── проверка одного адреса ───────────────────────────

REASONS = {
    "ok": "работает",
    "timeout": "таймаут: нет ответа (похоже на дроп DPI)",
    "freeze": "заморозка: данные пошли и остановились",
    "reset": "соединение сброшено",
    "tls": "ошибка TLS (сертификат или обрыв рукопожатия)",
    "dns": "адрес не определился или недоступен",
    "connect": "не удалось подключиться",
    "short": "сервер ответил, но мало данных",
    "error": "другая ошибка",
}
_CURL_REASON = {28: "timeout", 6: "dns", 7: "connect", 35: "tls", 60: "tls", 52: "reset",
                56: "reset", 55: "reset", 92: "reset", 18: "freeze", 16: "reset", 97: "dns"}


@dataclass
class Probe:
    target: Target
    ok: bool
    reason: str
    code: int = 0
    size: int = 0
    secs: float = 0.0


def _judge(t: Target, code: int, size: int, secs: float, err: int, handshake: float = 0) -> Probe:
    if err:
        reason = _CURL_REASON.get(err, "error")
        # Рукопожатие прошло, а данных нет: первая TLS-запись тоже могла не докачаться,
        # поэтому заморозка возможна и при нуле полученных байт.
        if reason in ("timeout", "reset") and (size > 0 or (handshake > 0 and not t.redirects)):
            reason = "freeze"
        return Probe(t, False, reason, code, size, secs)
    if not code:
        return Probe(t, False, "error", code, size, secs)
    if t.min_bytes and size < t.min_bytes:
        return Probe(t, False, "short", code, size, secs)
    return Probe(t, True, "ok", code, size, secs)


def _probe_cffi(t: Target, port: int | None, timeout: float, fingerprint: str,
                verify: bool | None = None) -> Probe:
    size = [0]
    code, err = 0, 0
    start = time.monotonic()

    def count(chunk: bytes):
        size[0] += len(chunk)

    kw = {}
    if port:
        kw["proxies"] = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
    if t.range_bytes:
        kw["headers"] = {"Range": f"bytes=0-{t.range_bytes - 1}"}
    if verify is not None:
        kw["verify"] = verify
    handshake = 0.0
    with cffi_requests.Session(impersonate=fingerprint, curl_infos=[CurlInfo.APPCONNECT_TIME]) as s:
        try:
            r = s.get(t.url, timeout=timeout, allow_redirects=True, max_redirects=5,
                      content_callback=count, **kw)
            code = r.status_code
        except Exception as e:      # curl_cffi поднимает свои типы ошибок с кодом libcurl
            err = getattr(e, "code", 0) or -1
            if not isinstance(err, int):
                err = int(getattr(err, "value", -1))
            r = getattr(e, "response", None)
            if r is not None:
                handshake = float((r.infos or {}).get(CurlInfo.APPCONNECT_TIME, 0) or 0)
    return _judge(t, code, size[0], time.monotonic() - start, err, handshake)


def _probe_curl(t: Target, port: int | None, timeout: float, extra: list[str] | None = None) -> Probe:
    cmd = ["curl", "-s", "-L", "--max-redirs", "5", "-o", "/dev/null",
           "-w", "%{http_code} %{size_download} %{time_appconnect}", "-m", str(timeout), *(extra or [])]
    if port and not extra:
        cmd += ["-x", f"socks5h://127.0.0.1:{port}"]
    elif port:
        cmd += ["-x", f"socks5://127.0.0.1:{port}"]
    if t.range_bytes:
        cmd += ["-r", f"0-{t.range_bytes - 1}"]
    start = time.monotonic()
    try:
        r = subprocess.run([*cmd, t.url], capture_output=True, text=True, timeout=timeout + 3)
        parts = r.stdout.split()
        code = int(parts[0]) if parts else 0
        size = int(parts[1]) if len(parts) > 1 else 0
        handshake = float(parts[2]) if len(parts) > 2 else 0.0
        return _judge(t, code, size, time.monotonic() - start, r.returncode, handshake)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return Probe(t, False, "timeout", secs=time.monotonic() - start)


def probe(t: Target, port: int | None, timeout: float, fingerprint: str = "firefox") -> Probe:
    """
    Адрес считается рабочим, только если ответ скачался целиком и в нужном объёме.
    ТСПУ часто пропускает рукопожатие и замораживает поток после ~16 КБ, поэтому код 200
    сам по себе ничего не доказывает. Отпечаток TLS — как у браузера: ClientHello от curl
    короче и устроен иначе, и стратегия может работать только для него.
    """
    if cffi_requests is not None:
        return _probe_cffi(t, port, timeout, fingerprint)
    return _probe_curl(t, port, timeout)


def check_targets(port: int | None, targets: list[Target], timeout: float,
                  fingerprint: str = "firefox") -> list[Probe]:
    with ThreadPoolExecutor(max_workers=min(12, len(targets) or 1)) as ex:
        return list(ex.map(lambda t: probe(t, port, timeout, fingerprint), targets))


def summarize(probes: list[Probe]) -> dict[str, tuple[int, int]]:
    scores: dict[str, list[int]] = {}
    for p in probes:
        s = scores.setdefault(p.target.service, [0, 0])
        s[0] += p.ok
        s[1] += 1
    return {k: (v[0], v[1]) for k, v in scores.items()}


# ─────────────────────────── запуск ciadpi ───────────────────────────

def expand_args(args: str, sni: str) -> list[str]:
    """{sni} → значение, затем разбор как в shell."""
    return shlex.split(args.replace("{sni}", shlex.quote(sni or "google.com")))


def _auto_uses_timeout(tokens: list[str]) -> bool:
    for i, tok in enumerate(tokens):
        value = None
        if tok.startswith("--auto="):
            value = tok[7:]
        elif tok == "--auto" or tok == "-A":
            value = tokens[i + 1] if i + 1 < len(tokens) else ""
        elif tok.startswith("-A"):
            value = tok[2:]
        if value is not None and any(v.startswith("t") for v in value.split(",")):
            return True
    return False


@lru_cache(maxsize=1)
def _timeout_flag() -> str:
    """
    Значение -T с лимитом байт: после первого ответа таймаут снимается, живые соединения не рвутся.
    Формат зависит от версии byedpi: новый -T s[:b], старый -T s[:p:c:b]. На новой версии старый
    формат не запускается вовсе, а на старой новый означал бы совсем другое.
    """
    try:
        text = subprocess.run([str(CIADPI), "--help"], capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.TimeoutExpired):
        return "-T3"
    return "-T3:1" if "--tcp-timeout" in text else "-T3:0:1:1"


def runtime_flags(tokens: list[str], ipv4_only: bool = True) -> list[str]:
    """
    Флаги, без которых стратегии работают хуже задуманного:
    -T  без него триггер -At срабатывает только на RST, а ТСПУ обычно молча дропает пакеты;
    -X  byedpi берёт первый адрес из DNS, и сломанный IPv6 провайдера ломает сайт целиком.
    """
    flags = []
    if ipv4_only and "-X" not in tokens and "--no-ipv6" not in tokens:
        flags.append("-X")
    has_timeout = any(t.startswith("-T") or t.startswith("--timeout") for t in tokens)
    if _auto_uses_timeout(tokens) and not has_timeout:
        flags.append(_timeout_flag())
    return flags


def build_argv(port: int, args: str, sni: str, ipv4_only: bool = True,
               log_level: int | None = None) -> list[str]:
    tokens = expand_args(args, sni)
    argv = ["-i", "127.0.0.1", "-p", str(port), *runtime_flags(tokens, ipv4_only)]
    if log_level is not None:
        argv += ["-x", str(log_level)]
    return [*argv, *tokens]


def port_busy(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def running_ciadpi(args: str, sni: str, ipv4_only: bool = True):
    """Временный ciadpi на свободном порту. Отдаёт порт или None, если он не запустился."""
    port = free_port()
    proc = subprocess.Popen([str(CIADPI), *build_argv(port, args, sni, ipv4_only)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            if proc.poll() is not None or port_busy(port):
                break
            time.sleep(0.05)
        yield None if proc.poll() is not None else port
    finally:
        proc.terminate()
        try:
            proc.wait(2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


# ─────────────────────────── стратегии ───────────────────────────

# Простые кандидаты в дополнение к списку ByeByeDPI, который собирался в основном под YouTube.
# Discord живёт на Cloudflare, и там часто помогает именно разбиение TLS-записи.
EXTRA_STRATEGIES = [
    "-r1+s -a1",
    "-r1+s -d1+s -a1",
    "-r1+s -s1+s -a1",
    "-r1+s -f-1 -t6 -a1",
    "-r1+s -d1+s -f-1 -t6 -a1",
    "-r1+s -d1+s -f-1 -S -a1",
    "-s1+s -f-1 -t6 -a1",
    "-d1+s -f-1 -t6 -a1",
    "-d1+s -f-1 -t6 -n {sni} -Qr -a1",
    "-o1+s -f-1 -t6 -a1",
    "-q1+s -f-1 -S -a1",
    "-r1+s -o1+s -a1",
    "--fake -1 --ttl 6 --disorder 1+s --tlsrec 1+s",
]


def load_strategies() -> list[str]:
    base: list[str] = []
    for path in (USER_STRATEGIES, APP_HOME / "strategies.list", HERE / "strategies.list"):
        try:
            lines = [l.strip() for l in path.read_text().splitlines()]
            base = [l for l in lines if l and not l.startswith("#")]
            if base:
                break
        except OSError:
            continue
    return list(dict.fromkeys([*(base or [DEFAULT_ARGS]), *EXTRA_STRATEGIES]))


def has_fake(args: str) -> bool:
    return bool(re.search(r"(^|\s)(-f|--fake)(\s|-?\d)", args))


def with_ttl(args: str, ttl: int) -> str:
    """Та же стратегия с другим TTL фейков. TTL зависит от того, на каком хопе стоит DPI."""
    args = re.sub(r"(^|\s)(?:-t\s*\d+|--ttl\s+\d+)(?=\s|$)", "", args).strip()
    return re.sub(r"(^|\s)((?:-f|--fake)(?:\s+-?\d\S*|-?\d\S*))", rf"\1\2 -t{ttl}", args)


def _limit_to_hosts(args: str, domains: list[str] | None) -> str:
    """Ограничивает доменами каждую группу стратегии, включая запасные после -A."""
    tokens = shlex.split(args)
    if not domains:
        return shlex.join(tokens)
    hosts = "-H:" + " ".join(domains)
    out = [hosts]
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        out.append(tok)
        if tok in ("-A", "--auto"):
            i += 1
            out.append(tokens[i])
            out.append(hosts)
        elif tok.startswith("-A") or tok.startswith("--auto="):
            out.append(hosts)
        i += 1
    return shlex.join(out)


def build_combo(per_service: dict[str, str], domains: dict[str, list[str]] | None = None,
                fallback: str | None = None) -> str:
    """
    Одна командная строка с разными стратегиями для разных сервисов.
    fallback без ограничения по доменам применяется ко всем остальным сайтам.
    """
    domains = domains or SERVICE_DOMAINS
    parts = [_limit_to_hosts(args, domains[svc]) for svc, args in per_service.items()]
    if fallback:
        parts.append(_limit_to_hosts(fallback, None))
    return " -An ".join(parts)


@dataclass
class Row:
    args: str
    scores: dict[str, tuple[int, int]]
    fails: list[str] = field(default_factory=list)
    kind: str = "base"          # base | ttl | combo

    def ratio(self, service: str) -> float:
        ok, total = self.scores.get(service, (0, 0))
        return ok / total if total else 0.0

    @property
    def total(self) -> float:
        return sum(self.ratio(s) for s in self.scores)

    def to_favorite(self) -> dict:
        return {"args": self.args, "scores": {k: list(v) for k, v in self.scores.items()}}


def rank(rows: list[Row]) -> list[Row]:
    return sorted(rows, key=lambda r: (-r.total, len(r.args)))


def evaluate_strategy(args: str, targets: list[Target], sni: str, timeout: float,
                  ipv4_only: bool, fingerprint: str, kind: str = "base") -> Row:
    with running_ciadpi(args, sni, ipv4_only) as port:
        if port is None:
            empty = {s: (0, sum(t.service == s for t in targets)) for s in {t.service for t in targets}}
            return Row(args, empty, ["ciadpi не принял эти аргументы"], kind)
        probes = check_targets(port, targets, timeout, fingerprint)
    fails = [f"{SERVICE_TITLES.get(p.target.service, p.target.service)} / {p.target.name}: "
             f"{REASONS[p.reason]}" for p in probes if not p.ok]
    return Row(args, summarize(probes), fails, kind)


TTL_VARIANTS = (3, 4, 5, 6, 7, 10, 12)
TTL_SEEDS = 3


def pick_strategies(strategies: list[str], targets: list[Target], sni: str, timeout: float,
                    ipv4_only: bool = True, fingerprint: str = "firefox",
                    on_progress: Callable[[int, int, str], None] = lambda *_: None,
                    on_row: Callable[[Row], None] = lambda _: None,
                    should_stop: Callable[[], bool] = lambda: False) -> tuple[list[Row], Row | None]:
    """
    1) все стратегии; 2) TTL для лучших с фейками, если сервис прошёл не полностью;
    3) если одной стратегии мало, отдельные правила для каждого сервиса с проверкой итога.
    Возвращает все строки и лучшую из них.
    """
    rows: list[Row] = []
    services = sorted({t.service for t in targets})
    queue = list(strategies)
    done = 0

    def run_one(args: str, kind: str) -> Row:
        row = evaluate_strategy(args, targets, sni, timeout, ipv4_only, fingerprint, kind)
        rows.append(row)
        on_row(row)
        return row

    for args in queue:
        if should_stop():
            return rows, _choose(rows, services)
        on_progress(done, len(queue), args)
        run_one(args, "base")
        done += 1

    refine: list[str] = []
    for svc in services:
        best = max((r.ratio(svc) for r in rows), default=0)
        if best >= 1:
            continue
        fakes = [r for r in rows if has_fake(r.args)]
        fakes.sort(key=lambda r: (-r.ratio(svc), len(r.args)))
        for r in fakes[:TTL_SEEDS]:
            refine += [with_ttl(r.args, ttl) for ttl in TTL_VARIANTS]
    known = {r.args for r in rows}
    refine = [a for a in dict.fromkeys(refine) if a not in known]
    for args in refine:
        if should_stop():
            return rows, _choose(rows, services)
        on_progress(done, len(queue) + len(refine), args)
        run_one(args, "ttl")
        done += 1

    best = _choose(rows, services)
    if best is None or len(services) < 2 or should_stop():
        return rows, best
    if all(best.ratio(s) >= max(r.ratio(s) for r in rows) for s in services):
        return rows, best       # одна стратегия уже лучшая для всех сервисов

    per_service = {}
    for svc in services:
        top = min(rows, key=lambda r: (-r.ratio(svc), len(r.args)))
        if top.ratio(svc) > 0:
            per_service[svc] = top.args
    if len(set(per_service.values())) < 2:
        return rows, best
    combo_args = build_combo(per_service, fallback=best.args)
    on_progress(done, done + 1, combo_args)
    combo = run_one(combo_args, "combo")
    # итог проверяем по факту: группы byedpi могут вести себя иначе, чем стратегии по отдельности
    return rows, (combo if combo.total >= best.total else best)


def _choose(rows: list[Row], services: list[str]) -> Row | None:
    alive = [r for r in rows if r.total > 0]
    return rank(alive)[0] if alive else None


# ─────────────────────────── VPN и DNS ───────────────────────────

def route_info(dest: str = "1.1.1.1") -> tuple[str | None, bool]:
    """Через какой интерфейс уходит трафик и похоже ли это на туннель VPN."""
    try:
        out = subprocess.run(["ip", "route", "get", dest], capture_output=True, text=True,
                             timeout=3).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None, False
    m = re.search(r"\bdev (\S+)", out)
    if not m:
        return None, False
    dev = m.group(1)
    sysdir = Path("/sys/class/net") / dev
    # у реальной сетевой карты и USB-модема есть device; PPPoE от провайдера тоже не VPN
    virtual = sysdir.exists() and not (sysdir / "device").exists()
    if re.match(r"(ppp|br|bond|vlan|veth|wwan)", dev) and not (sysdir / "tun_flags").exists():
        virtual = False
    return dev, virtual


NETS = {
    "google": [ipaddress.ip_network(n) for n in (
        "8.8.4.0/24", "8.8.8.0/24", "34.0.0.0/9", "35.184.0.0/13", "64.233.160.0/19",
        "66.102.0.0/20", "66.249.64.0/19", "72.14.192.0/18", "74.125.0.0/16",
        "108.177.0.0/17", "142.250.0.0/15", "172.217.0.0/16", "172.253.0.0/16",
        "173.194.0.0/16", "192.178.0.0/15", "209.85.128.0/17", "216.58.192.0/19",
        "216.239.32.0/19", "2001:4860::/32", "2404:6800::/32", "2607:f8b0::/32",
        "2800:3f0::/32", "2a00:1450::/32", "2c0f:fb50::/32")],
    "cloudflare": [ipaddress.ip_network(n) for n in (
        "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "188.114.96.0/20",
        "198.41.128.0/17", "141.101.64.0/18", "2606:4700::/32", "2a06:98c0::/29")],
}

# Видеосерверы rr*.googlevideo.com сюда не входят: они часто стоят в сети самого провайдера,
# и их адрес законно не попадает в диапазоны Google.
DNS_HOSTS = [("www.youtube.com", "google"), ("i.ytimg.com", "google"),
             ("redirector.googlevideo.com", "google"), ("discord.com", "cloudflare"),
             ("gateway.discord.gg", "cloudflare"), ("cdn.discordapp.com", "cloudflare")]


def in_nets(ip: str, nets_key: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in NETS[nets_key])


def system_resolve(host: str) -> list[str]:
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
    except OSError:
        return []


def doh_resolve(host: str, socks_port: int | None) -> list[str]:
    """DNS-over-HTTPS (JSON API). Сначала напрямую, потом через byedpi, если он запущен."""
    endpoints = [
        f"https://dns.google/resolve?name={host}&type=A",
        f"https://cloudflare-dns.com/dns-query?name={host}&type=A",
        f"https://dns.quad9.net:5053/dns-query?name={host}&type=A",
    ]
    for via in [None] + ([socks_port] if socks_port else []):
        for url in endpoints:
            cmd = ["curl", "-s", "-m", "5", "-H", "accept: application/dns-json", url]
            if via:
                cmd[1:1] = ["-x", f"socks5h://127.0.0.1:{via}"]
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout
                ips = [a["data"] for a in json.loads(out).get("Answer", []) if a.get("type") == 1]
                if ips:
                    return sorted(set(ips))
            except (OSError, ValueError, subprocess.TimeoutExpired):
                continue
    return []


@dataclass
class DnsResult:
    host: str
    system: list[str]
    doh: list[str]
    verdict: str
    bad: bool


def check_dns(socks_port: int | None = None) -> list[DnsResult]:
    def one(item):
        host, nets = item
        sys_ips, doh_ips = system_resolve(host), doh_resolve(host, socks_port)
        if not sys_ips:
            verdict, bad = "системный DNS не отдаёт адрес", True
        elif not any(in_nets(ip, nets) for ip in sys_ips):
            verdict, bad = "адрес не из сетей сервиса — похоже на подмену", True
        else:
            verdict, bad = "норма", False
        return DnsResult(host, sys_ips, doh_ips, verdict, bad)

    with ThreadPoolExecutor(max_workers=len(DNS_HOSTS)) as ex:
        return list(ex.map(one, DNS_HOSTS))


# ─────────────────────────── браузер, Discord, PAC ───────────────────────────

def _which(cmd: str) -> bool:
    from shutil import which
    return which(cmd) is not None


def write_firefox_profile(port: int) -> Path:
    """Отдельный профиль: не трогает основной и запускается, даже если Firefox уже открыт."""
    FIREFOX_PROFILE.mkdir(parents=True, exist_ok=True)
    prefs = {
        "network.proxy.type": 1,
        "network.proxy.socks": "127.0.0.1",
        "network.proxy.socks_port": port,
        "network.proxy.socks_version": 5,
        "network.proxy.socks_remote_dns": True,
        "network.proxy.socks5_remote_dns": True,
        "network.proxy.http": "",
        "network.proxy.ssl": "",
        "network.proxy.share_proxy_settings": False,
        "network.http.http3.enable": False,
        # DNS идёт через byedpi; ECH на Cloudflare сам по себе становится поводом для блокировки
        "network.trr.mode": 5,
        "network.dns.echconfig.enabled": False,
        "network.dns.http3_echconfig.enabled": False,
        "browser.shell.checkDefaultBrowser": False,
        "browser.aboutwelcome.enabled": False,
        "datareporting.policy.dataSubmissionEnabled": False,
    }
    body = "".join(f'user_pref("{k}", {json.dumps(v)});\n' for k, v in prefs.items())
    (FIREFOX_PROFILE / "user.js").write_text(body)
    return FIREFOX_PROFILE


def browser_command(cfg: dict, port: int, url: str | None = None) -> list[str] | None:
    """Команда запуска браузера через прокси. None — подходящего браузера нет."""
    custom = (cfg.get("browser_cmd") or "").strip()
    if custom:
        parts = shlex.split(custom.format(port=port))
        return ([*parts, url] if url else parts) if parts and _which(parts[0]) else None
    for name in ("firefox", "firefox-esr", "librewolf"):
        if _which(name):
            profile = write_firefox_profile(port)
            return [name, "--profile", str(profile), *([url] if url else [])]
    for name in ("chromium", "chromium-browser", "brave-browser", "brave", "google-chrome-stable",
                 "google-chrome", "vivaldi-stable"):
        if _which(name):
            data = CFG_DIR / "chromium-profile"
            data.mkdir(parents=True, exist_ok=True)
            return [name, f"--proxy-server=socks5://127.0.0.1:{port}", f"--user-data-dir={data}",
                    *([url] if url else [])]
    return None


def discord_command(cfg: dict, port: int) -> list[str] | None:
    """Discord на Electron берёт прокси только из флага и не видит системные настройки."""
    flag = f"--proxy-server=socks5://127.0.0.1:{port}"
    custom = (cfg.get("discord_cmd") or "").strip()
    if custom:
        parts = shlex.split(custom.format(port=port))
        return parts if parts and _which(parts[0]) else None
    for name in ("discord", "Discord", "discord-canary", "discord-ptb", "vesktop"):
        if _which(name):
            return [name, flag]
    for path in ("/opt/discord/Discord", "/opt/Discord/Discord", "/usr/share/discord/Discord"):
        if Path(path).exists():
            return [path, flag]
    if _which("flatpak"):
        for app in ("com.discordapp.Discord", "dev.vencord.Vesktop"):
            r = subprocess.run(["flatpak", "info", app], capture_output=True)
            if r.returncode == 0:
                return ["flatpak", "run", app, flag]
    return None


def write_pac(port: int, extra_domains: list[str] | None = None) -> Path:
    """
    PAC для основного профиля браузера: через byedpi идут только YouTube и Discord.
    Если прокси выключен, браузер уйдёт напрямую и интернет не пропадёт.
    """
    domains = [d for lst in SERVICE_DOMAINS.values() for d in lst] + list(extra_domains or [])
    body = (
        f"var DOMAINS = {json.dumps(sorted(set(domains)))};\n"
        "function FindProxyForURL(url, host) {\n"
        "  host = host.toLowerCase();\n"
        "  for (var i = 0; i < DOMAINS.length; i++) {\n"
        "    var d = DOMAINS[i];\n"
        '    if (host === d || dnsDomainIs(host, "." + d)) {\n'
        f'      return "SOCKS5 127.0.0.1:{port}; DIRECT";\n'
        "    }\n"
        "  }\n"
        '  return "DIRECT";\n'
        "}\n"
    )
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    PAC_FILE.write_text(body)
    return PAC_FILE


# ─────────────────────────── отчёт ───────────────────────────

# ─────────────────────────── голос Discord (nfqws) ───────────────────────────

VOICE_HELPER = Path("/usr/local/sbin/byedpi-tg-voice")
VOICE_STATE = Path("/run/byedpi-tg-voice.state")
# Названия совпадают с профилями в voice/byedpi-tg-voice
VOICE_PROFILES = {
    "quic6": "Фейк QUIC ×6 (основной)",
    "quic11": "Фейк QUIC ×11",
    "stun3": "Фейк STUN и QUIC ×3",
    "wide": "Любой UDP на голосовых портах",
}
VOICE_NEED_PASSWORD = -1


@dataclass(frozen=True)
class VoiceStatus:
    running: bool
    iface: str = ""
    profile: str = ""


def voice_status(state_file: Path = VOICE_STATE, proc: Path = Path("/proc")) -> VoiceStatus:
    """Работает ли режим. Прав root не нужно: хелпер оставляет файл состояния в /run."""
    try:
        state = dict(line.split("=", 1) for line in state_file.read_text().split())
        comm = (proc / state["pid"] / "comm").read_text().strip()
    except (OSError, ValueError, KeyError):
        return VoiceStatus(False)
    if comm != "nfqws":
        return VoiceStatus(False)
    return VoiceStatus(True, state.get("iface", ""), state.get("profile", ""))


def voice_run(action: str, profile: str | None = None, password: str | None = None) -> tuple[int, str]:
    """
    Запускает хелпер через sudo. Без пароля пробует sudo -n и возвращает VOICE_NEED_PASSWORD,
    если пароль нужен. Пароль передаётся только в stdin sudo и нигде не сохраняется.
    """
    sudo = ["sudo", "-n"] if password is None else ["sudo", "-S", "-k", "-p", ""]
    args = [str(VOICE_HELPER), action] + ([profile] if profile else [])
    try:
        r = subprocess.run(sudo + args, capture_output=True, text=True, timeout=30,
                           input="" if password is None else password + "\n",
                           env={**os.environ, "LC_ALL": "C"})
    except FileNotFoundError:
        return 1, f"Нет sudo. Запусти от root: {' '.join(args)}"
    except subprocess.TimeoutExpired:
        return 1, "Хелпер не ответил за 30 секунд."
    text = (r.stderr.strip() or r.stdout.strip())
    if r.returncode != 0 and "password is required" in r.stderr:
        return VOICE_NEED_PASSWORD, ""
    if r.returncode != 0 and ("incorrect password" in r.stderr or "try again" in r.stderr):
        return 1, "Неверный пароль."
    return r.returncode, text


VPN_WARNING = ("Трафик сейчас идёт через VPN ({dev}). Проверки показывают работу VPN, а не обхода DPI: "
               "пройдёт почти любая стратегия. Выключи VPN (и его kill switch), затем проверяй снова.")


def _fmt_probe(p: Probe) -> str:
    return (f"  {'OK ' if p.ok else 'XX '} {SERVICE_TITLES.get(p.target.service, '?'):8} "
            f"{p.target.name:14} код={p.code or '-':<4} байт={p.size:<8} {p.secs:4.1f}с  "
            f"{'' if p.ok else REASONS[p.reason]}")


def diagnose(cfg: dict, out: Callable[[str], None] = print, pick: bool = False,
             apply_best: bool = False) -> None:
    timeout = float(cfg.get("probe_timeout", 8))
    fp = cfg.get("probe_fingerprint", "firefox")
    sni = cfg.get("fake_sni", "google.com")
    ipv4 = bool(cfg.get("ipv4_only", True))

    out(f"ByeDPI x TG: диагностика, {time.strftime('%Y-%m-%d %H:%M')}")
    out(f"Ядро {platform.release()}, python {platform.python_version()}")
    try:
        ver = subprocess.run([str(CIADPI), "--version"], capture_output=True, text=True, timeout=3).stdout.strip()
    except OSError:
        ver = "НЕ НАЙДЕН"
    out(f"ciadpi: {ver}")
    out(f"Проверка TLS: {'curl_cffi, отпечаток ' + fp if cffi_requests else 'curl (менее точно, запусти install.sh)'}")

    dev, is_vpn = route_info()
    out(f"Маршрут в интернет: {dev or 'не определён'}{' — ТУННЕЛЬ VPN' if is_vpn else ''}")
    if is_vpn:
        out("!! " + VPN_WARNING.format(dev=dev))

    voice = voice_status()
    if voice.running:
        out(f"Голос Discord: nfqws работает, {voice.iface}, профиль {voice.profile}")
    else:
        out(f"Голос Discord: {'выключен' if VOICE_HELPER.exists() else 'не установлен'}")

    out("\n== DNS ==")
    dns = check_dns()
    for r in dns:
        out(f"  {'XX ' if r.bad else 'OK '} {r.host}: система {', '.join(r.system[:3]) or '-'}; "
            f"DoH {', '.join(r.doh[:3]) or 'нет ответа'}{'; ' + r.verdict if r.bad else ''}")

    node = discover_video_node()
    out(f"\nВидеосервер: {node or 'не определён напрямую'}")
    targets = all_targets(cfg, node)

    out("\n== Напрямую, без byedpi ==")
    direct = check_targets(None, targets, timeout, fp)
    for p in direct:
        out(_fmt_probe(p))

    args = cfg.get("byedpi_args", DEFAULT_ARGS)
    out(f"\n== Через текущую стратегию ==\n  {args}")
    row_probes = None
    with running_ciadpi(args, sni, ipv4) as port:
        if port is None:
            out("  ciadpi не запустился с этими аргументами")
        else:
            row_probes = check_targets(port, targets, timeout, fp)
            for p in row_probes:
                out(_fmt_probe(p))

    if pick:
        if not node and row_probes is not None:
            with running_ciadpi(args, sni, ipv4) as port:
                node = discover_video_node(port) if port else None
            targets = all_targets(cfg, node)
        strategies = load_strategies()
        out(f"\n== Подбор: {len(strategies)} стратегий, адресов {len(targets)} ==")

        def row_line(r: Row):
            score = "  ".join(f"{SERVICE_TITLES[k]} {v[0]}/{v[1]}" for k, v in sorted(r.scores.items()))
            out(f"  [{r.kind:5}] {score}  {r.args}")

        rows, best = pick_strategies(strategies, targets, sni, timeout, ipv4, fp, on_row=row_line)
        fails: dict[str, int] = {}
        for r in rows:
            for f in r.fails:
                fails[f] = fails.get(f, 0) + 1
        out("\n== Частые причины отказа ==")
        for text, n in sorted(fails.items(), key=lambda kv: -kv[1])[:15]:
            out(f"  {n:3}  {text}")
        out("\n== Лучшие ==")
        for r in rank(rows)[:8]:
            row_line(r)
        if best:
            out(f"\nВыбрана: {best.args}")
            for s in sorted(best.scores):
                out(f"  {SERVICE_TITLES[s]}: {best.scores[s][0]}/{best.scores[s][1]}")
            if apply_best:
                cfg["byedpi_args"] = best.args
                cfg["favorites"] = [r.to_favorite() for r in rank(rows)[:8]]
                save_cfg(cfg)
                out("Сохранена в конфиг. Запусти или перезапусти byedpi в приложении.")
        else:
            out("\nНи одна стратегия не прошла ни одного адреса.")


def main() -> int:
    ap = argparse.ArgumentParser(description="Диагностика сети и подбор стратегий byedpi")
    ap.add_argument("--pick", action="store_true", help="также подобрать стратегию (до ~15 минут)")
    ap.add_argument("--apply", action="store_true", help="сохранить лучшую стратегию в конфиг")
    ap.add_argument("--force", action="store_true", help="подбирать, даже если активен VPN")
    ap.add_argument("--voice", choices=("start", "stop", "status"), help="голос Discord через nfqws (спросит пароль sudo)")
    ap.add_argument("--voice-profile", choices=sorted(VOICE_PROFILES), help="профиль для --voice start")
    a = ap.parse_args()
    if a.voice:
        if not VOICE_HELPER.exists():
            print("Режим не установлен. Выполни: ./install.sh voice", file=sys.stderr)
            return 1
        extra = [a.voice_profile or load_cfg()["voice_profile"]] if a.voice == "start" else []
        return subprocess.run(["sudo", str(VOICE_HELPER), a.voice, *extra]).returncode
    dev, is_vpn = route_info()
    if a.pick and is_vpn and not a.force:
        print(VPN_WARNING.format(dev=dev), file=sys.stderr)
        print("Подбор отменён. Запусти с --force, если всё равно нужно.", file=sys.stderr)
        return 2
    cfg = load_cfg()
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    with REPORT_FILE.open("w") as f:
        def out(line: str):
            print(line, flush=True)
            f.write(line + "\n")
            f.flush()
        diagnose(cfg, out, pick=a.pick, apply_best=a.apply)
    print(f"\nОтчёт сохранён: {REPORT_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
