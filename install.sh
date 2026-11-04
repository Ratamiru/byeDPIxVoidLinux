#!/bin/sh
# Установка ByeDPI × TG Desktop (рассчитано на Void Linux, работает и на других дистрах)
#   ./install.sh            — установить / обновить
#   ./install.sh voice      — добавить голос Discord: собрать nfqws и поставить хелпер (нужен sudo)
#   ./install.sh uninstall  — удалить (конфиг в ~/.config/byedpi-tg остаётся)
set -eu

APP="${BYEDPI_TG_HOME:-$HOME/.local/share/byedpi-tg}"
BIN="$HOME/.local/bin"
DESKTOP="$HOME/.local/share/applications"
SRC="$(cd "$(dirname "$0")" && pwd)"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

# Сборка закреплена на проверенной версии: бинарник будет запускаться от root
ZAPRET_TAG=v72.13
ZAPRET_COMMIT=87e058624c72863db53bdaf7fb6f16576dddb6ab
VOICE_LIB=/usr/local/lib/byedpi-tg
VOICE_BIN=/usr/local/sbin/byedpi-tg-voice

if [ "${1:-}" = "voice" ]; then
    if command -v xbps-install >/dev/null 2>&1; then
        say "Ставлю зависимости сборки nfqws через xbps (нужен sudo)"
        sudo xbps-install -Sy git gcc make iptables libnetfilter_queue-devel libmnl-devel libnfnetlink-devel zlib-devel
    else
        echo "Нужны: git, gcc, make, iptables и dev-пакеты libnetfilter_queue, libmnl, libnfnetlink, zlib." >&2
    fi
    command -v iptables >/dev/null || { echo "Нужен iptables." >&2; exit 1; }
    BUILD="$(mktemp -d)"
    trap 'rm -rf "$BUILD"' EXIT
    say "Собираю nfqws из zapret $ZAPRET_TAG"
    git clone --depth 1 --branch "$ZAPRET_TAG" -q https://github.com/bol-van/zapret "$BUILD/zapret" 2>/dev/null
    got="$(git -C "$BUILD/zapret" rev-parse HEAD)"
    if [ "$got" != "$ZAPRET_COMMIT" ]; then
        echo "Метка $ZAPRET_TAG указывает на другой коммит: $got. Останавливаюсь." >&2
        exit 1
    fi
    make -C "$BUILD/zapret/nfq" -s
    say "Ставлю хелпер и nfqws в /usr/local (нужен sudo)"
    [ ! -x "$VOICE_BIN" ] || sudo "$VOICE_BIN" stop >/dev/null
    sudo install -d -o root -g root -m 755 "$VOICE_LIB" "$VOICE_LIB/fake"
    sudo install -o root -g root -m 755 "$BUILD/zapret/nfq/nfqws" "$VOICE_LIB/nfqws"
    sudo install -o root -g root -m 644 "$BUILD/zapret/files/fake/quic_initial_www_google_com.bin" \
        "$BUILD/zapret/files/fake/stun.bin" "$VOICE_LIB/fake/"
    sudo install -o root -g root -m 755 "$SRC/voice/byedpi-tg-voice" "$VOICE_BIN"
    say "Готово. Включай карточкой «Голос Discord» или: byedpi-tg-diag --voice start"
    exit 0
fi

if [ "${1:-}" = "uninstall" ]; then
    if [ -e "$VOICE_BIN" ]; then
        say "Убираю режим голоса (нужен sudo)"
        sudo "$VOICE_BIN" stop >/dev/null || true
        sudo rm -rf "$VOICE_LIB" "$VOICE_BIN"
    fi
    rm -rf "$APP" "$BIN/byedpi-tg" "$BIN/byedpi-tg-diag" "$DESKTOP/byedpi-tg.desktop"
    say "Удалено. Конфиг оставлен в ~/.config/byedpi-tg"
    exit 0
fi

# 1. Системные пакеты
if command -v xbps-install >/dev/null 2>&1; then
    say "Ставлю зависимости через xbps (нужен sudo)"
    sudo xbps-install -Sy git gcc make python3 curl xdg-utils
elif ! command -v gcc >/dev/null || ! command -v git >/dev/null || ! command -v python3 >/dev/null; then
    echo "Нужны: git, gcc, make, python3, curl, xdg-utils — поставь их пакетным менеджером." >&2
    exit 1
fi

# PySide6 из pip — это glibc-колёса, на musl-Void не встанут
if ldd --version 2>&1 | grep -qi musl; then
    echo "Похоже, у тебя musl-вариант Void: колёса PySide6 из pip не подойдут." >&2
    echo "Поставь PySide6 из системы и пересоздай venv с --system-site-packages." >&2
    exit 1
fi

mkdir -p "$APP" "$BIN" "$DESKTOP"

clone_or_pull() {  # $1 = url, $2 = dir
    if [ -d "$2/.git" ]; then
        git -C "$2" pull --ff-only -q
    else
        git clone --depth 1 -q "$1" "$2"
    fi
}

# 2. byedpi
say "Собираю byedpi"
clone_or_pull https://github.com/hufrea/byedpi "$APP/byedpi"
make -C "$APP/byedpi" -s >/dev/null 2>&1 || make -C "$APP/byedpi"
test -x "$APP/byedpi/ciadpi"

# 3. tg-ws-proxy
say "Качаю tg-ws-proxy"
clone_or_pull https://github.com/Flowseal/tg-ws-proxy "$APP/tg-ws-proxy"

# 4. Python-окружение
say "Создаю venv и ставлю PySide6 + зависимости прокси"
[ -x "$APP/venv/bin/python" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q PySide6-Essentials certifi "httpx[http2]" cryptography
# Отпечаток браузера в проверках. Без него приложение работает, но подбор менее точен.
"$APP/venv/bin/pip" install -q --upgrade curl_cffi || \
    echo "Не удалось поставить curl_cffi: проверки пойдут через curl с его отпечатком TLS." >&2

# 5. Само приложение
install -m 755 "$SRC/byedpi_tg.py" "$APP/byedpi_tg.py"
install -m 644 "$SRC/dpi_core.py" "$APP/dpi_core.py"
install -m 644 "$SRC/strategies.list" "$APP/strategies.list"
cat > "$BIN/byedpi-tg" <<EOF
#!/bin/sh
exec "$APP/venv/bin/python" "$APP/byedpi_tg.py" "\$@"
EOF
cat > "$BIN/byedpi-tg-diag" <<EOF
#!/bin/sh
exec "$APP/venv/bin/python" "$APP/dpi_core.py" "\$@"
EOF
chmod +x "$BIN/byedpi-tg" "$BIN/byedpi-tg-diag"

sed "s|@BIN@|$BIN|" "$SRC/byedpi-tg.desktop" > "$DESKTOP/byedpi-tg.desktop"

say "Готово. Запуск: byedpi-tg  (или через лаунчер приложений)"
say "Диагностика из консоли: byedpi-tg-diag --pick --apply  (VPN должен быть выключен)"
case ":$PATH:" in *":$BIN:"*) ;; *) echo "   ~/.local/bin нет в PATH — добавь его или запускай $BIN/byedpi-tg";; esac
