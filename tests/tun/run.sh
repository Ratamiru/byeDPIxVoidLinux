#!/bin/sh
# Проверяет tun/byedpi-tg-tun под настоящим root в отдельном сетевом namespace.
# Хост не затрагивается: правила, интерфейсы и iptables живут внутри namespace.
# Вместо ciadpi и hev-socks5-tunnel — заглушки; «интернет» — tun-интерфейс, который пишет лог пакетов.
#   sudo tests/tun/run.sh
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "Нужен root (тест работает в своём сетевом namespace)." >&2; exit 1; }
command -v ip >/dev/null && command -v iptables >/dev/null && command -v setpriv >/dev/null \
    || { echo "Нужны ip, iptables и setpriv." >&2; exit 1; }
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
chmod 755 "$WORK"
cp "$HERE/../../tun/byedpi-tg-tun" "$HERE/inside.sh" "$HERE/tunlog.py" "$HERE/probe.py" "$WORK/"
unshare --net sh "$WORK/inside.sh" "$WORK" | tee "$WORK/out.txt"
grep -q '^RESULT PASS' "$WORK/out.txt"
