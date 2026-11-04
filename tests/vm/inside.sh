#!/bin/sh
# Выполняется внутри виртуальной машины от root.
S=/tmp/share
L=/tmp/lib; mkdir -p $L/fake
PASS=0; FAILS=0
ok() { echo "ok   - $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL - $1${2:+: $2}"; FAILS=$((FAILS+1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "ожидалось [$3], получено [$2]"; fi; }

# Хелпер без изменений, кроме путей к бинарнику
mkhelper() {
    sed -e "s|^NFQWS=.*|NFQWS=$1|" -e "s|^FAKE_DIR=.*|FAKE_DIR=$L/fake|" $S/byedpi-tg-voice > /tmp/helper
    chmod +x /tmp/helper
}
cat > $L/stub <<'STUB'
#!/bin/sh
# Заглушка nfqws: понимает --dry-run, --daemon и --pidfile и просто живёт, не занимая очередь.
for a; do case "$a" in --dry-run) [ -e /tmp/stub_bad_args ] && exit 1; exit 0;; --pidfile=*) pf=${a#--pidfile=};; esac; done
[ "${1:-}" = child ] && { trap 'exit 0' TERM; while :; do sleep 0.2; done; }
[ -e /tmp/stub_die ] && exit 0
"$0" child </dev/null >/dev/null 2>&1 &
echo $! > "$pf"
printf '%s\n' "$*" > /tmp/stub_args
STUB
mkdir -p $L/s; cp $L/stub $L/s/nfqws; chmod +x $L/s/nfqws
mkhelper $L/s/nfqws
modprobe veth; modprobe nf_conntrack; modprobe iptable_mangle

ip netns add cli; ip netns add srv
ip link add wan0 netns cli type veth peer name wan1 netns srv
ip link add alt0 netns cli type veth peer name alt1 netns srv
ip -n cli addr add 10.9.0.1/24 dev wan0; ip -n srv addr add 10.9.0.2/24 dev wan1
ip -n cli addr add 10.8.0.1/24 dev alt0; ip -n srv addr add 10.8.0.2/24 dev alt1
for n in cli srv; do ip -n $n link set lo up; done
ip -n cli link set wan0 up; ip -n cli link set alt0 up; ip -n srv link set wan1 up; ip -n srv link set alt1 up
ip -n srv addr add 10.7.0.9/32 dev wan1; ip -n srv addr add 10.7.0.10/32 dev wan1
ip -n cli route add 10.7.0.9 via 10.9.0.2 dev wan0   # как сервер VPN: отдельный маршрут
ip -n srv route add 10.9.0.0/24 dev wan1 2>/dev/null

CLI="ip netns exec cli"; SRV="ip netns exec srv"
H="$CLI /tmp/helper"
PY=/usr/bin/python3
send() { $CLI $PY $S/udp_probe.py send "$@"; }
recv_bg() { $SRV $PY $S/udp_probe.py recv "$1" "$2" > /tmp/recv.$1 & sleep 1; }
queued() { $CLI iptables -w -t mangle -nvxL BYEDPI_VOICE 2>/dev/null | awk '/NFQUEUE/ {print $1}'; }
hooks() { $CLI iptables -w -t mangle -S POSTROUTING | grep -c BYEDPI_VOICE; }
snap() { $CLI iptables -w -t mangle -S; }
base=$(snap)
case "$base" in *"-P POSTROUTING ACCEPT"*) ok "таблица mangle доступна";; *) bad "таблица mangle доступна" "$base";; esac

# --- отказы до каких-либо изменений
$H start nosuch wan0 >/dev/null 2>&1; check "неизвестный профиль отклонён" $? 1
$H start quic6 'wan0;id' >/dev/null 2>&1; check "инъекция в имени интерфейса отклонена" $? 1
$H start quic6 ../wan0 >/dev/null 2>&1; check "путь вместо интерфейса отклонён" $? 1
$H start quic6 nonexistent >/dev/null 2>&1; check "несуществующий интерфейс отклонён" $? 1
touch /tmp/stub_bad_args; $H start quic6 wan0 >/dev/null 2>&1; check "dry-run не прошёл: отказ" $? 1; rm /tmp/stub_bad_args
check "после отказов правила не изменились" "$(snap)" "$base"
$CLI $PY -c 'import os; os.setgid(65534); os.setuid(65534); os.execv("/tmp/helper", ["helper", "stop"])' 2>/tmp/err; rc=$?; check "без root отказ" "$rc $(cat /tmp/err)" "1 Нужны права root."

# --- запуск
$H start quic6 wan0 >/tmp/err 2>&1; rc=$?; [ $rc = 0 ] || echo "# $(cat /tmp/err)"; check "запуск" $rc 0
check "одно правило в POSTROUTING" "$(hooks)" 1
pid=$(cat /run/byedpi-tg-voice.pid)
check "nfqws живёт" "$(cat /proc/$pid/comm)" nfqws
check "состояние читается" "$(cut -d= -f2 /run/byedpi-tg-voice.state | tr '\n' ' ')" "$pid wan0 quic6 "
$H status >/dev/null; check "status=0" $? 0
grep -q -- '--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun' /tmp/stub_args && ok "nfqws получил фильтры" || bad "nfqws получил фильтры" "$(cat /tmp/stub_args)"

# --- что попадает в очередь. Заглушка очередь не занимает: --queue-bypass обязан пропускать пакеты
recv_bg 50000 3; send 10.9.0.2 50000 30 discord; wait
check "голосовой порт: все пакеты дошли без потребителя очереди" "$(cat /tmp/recv.50000)" "74:30"
check "в очередь только первые 12 пакетов потока" "$(queued)" 12
before=$(queued); recv_bg 19300 3; send 10.9.0.2 19300 5 stun; wait
check "второй диапазон портов" "$(($(queued)-before))" 5
before=$(queued); recv_bg 40000 3; send 10.9.0.2 40000 5 other; wait
check "чужой порт дошёл" "$(cat /tmp/recv.40000)" "64:5"
check "чужой порт не в очереди" "$(($(queued)-before))" 0
before=$(queued); recv_bg 50001 3; send 10.8.0.2 50001 5 discord; wait
check "другой интерфейс не в очереди" "$(($(queued)-before))" 0
before=$(queued); recv_bg 50002 3; send 10.7.0.9 50002 5 discord; wait
check "адрес с отдельным маршрутом (VPN) не в очереди" "$(($(queued)-before))" 0
check "и дошёл" "$(cat /tmp/recv.50002)" "74:5"

# --- перезапуск и падение
$H start quic11 wan0 >/dev/null; check "перезапуск" $? 0
check "правило не задвоилось" "$(hooks)" 1
[ -d /proc/$pid ] && bad "старый процесс завершён" || ok "старый процесс завершён"
kill -9 "$(cat /run/byedpi-tg-voice.pid)"; sleep 0.2
recv_bg 50003 3; send 10.9.0.2 50003 20 discord; wait
check "nfqws убит: голос идёт дальше" "$(cat /tmp/recv.50003)" "74:20"
$H status >/dev/null; check "после падения status=3" $? 3

# --- остановка
$H stop >/dev/null; check "stop" $? 0
check "правила полностью убраны" "$(snap)" "$base"
[ -e /run/byedpi-tg-voice.state ] && bad "файл состояния удалён" || ok "файл состояния удалён"
$H stop >/dev/null; check "повторный stop" $? 0

# --- откат, если nfqws сразу умирает или правила не добавились
touch /tmp/stub_die; $H start quic6 wan0 >/dev/null 2>&1; check "nfqws умер: отказ" $? 1; rm /tmp/stub_die
check "после отказа нет правил" "$(snap)" "$base"
$H start quic6 wan0 >/dev/null 2>&1
$CLI iptables -w -t mangle -S | grep -q BYEDPI && ok "снова запускается" || bad "снова запускается"
$H stop >/dev/null
$CLI iptables -w -t mangle -N BYEDPI_VOICE; $CLI iptables -w -t mangle -A POSTROUTING -o wan0 -j BYEDPI_VOICE
$H stop >/dev/null; check "stop убирает остатки без файла состояния" "$(snap)" "$base"

# --- маршрут по умолчанию
ip -n cli route add default via 10.9.0.2 dev wan0
$H start quic6 >/dev/null 2>&1; check "виртуальный маршрут без явного интерфейса: отказ" $? 1
check "ничего не добавлено" "$(snap)" "$base"

# --- настоящий nfqws, если передан: фейки должны уходить перед исходным пакетом
if [ -x $S/nfqws.real ]; then
    echo "# настоящий nfqws"
    ip -n cli route del default
    mkdir -p $L/r; cp $S/nfqws.real $L/r/nfqws; mkhelper $L/r/nfqws
    head -c 1200 /dev/zero > $L/fake/quic_initial_www_google_com.bin; head -c 100 /dev/zero > $L/fake/stun.bin
    port=50010
    for p in quic6 quic11 stun3 wide; do
        $H start $p wan0 >/tmp/err 2>&1; check "профиль $p запустился" $? 0
        grep -q "^ *2046 " /proc/net/netfilter/nfnetlink_queue && ok "$p: очередь занята" || bad "$p: очередь занята"
        recv_bg $port 3; send 10.9.0.2 $port 3 discord; wait
        echo "# $p: на сервере размер:количество = $(cat /tmp/recv.$port)"
        case "$(cat /tmp/recv.$port)" in *1200:*) ok "$p: сервер видит фейк";; *) bad "$p: сервер видит фейк" "$(cat /tmp/recv.$port)";; esac
        case "$(cat /tmp/recv.$port)" in *74:3*) ok "$p: настоящие пакеты дошли";; *) bad "$p: настоящие пакеты дошли";; esac
        port=$((port+1))
        $H stop >/dev/null
    done
    $H start quic6 wan0 >/dev/null
    recv_bg 50020 3; send 10.9.0.2 50020 3 other; wait
    check "quic6: чужой протокол без фейков" "$(cat /tmp/recv.50020)" "64:3"
    $H stop >/dev/null
fi

if [ "$FAILS" = 0 ]; then echo "RESULT PASS $PASS"; else echo "RESULT FAIL $FAILS из $((PASS+FAILS))"; fi
