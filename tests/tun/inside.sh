#!/bin/sh
# Выполняется от root внутри отдельного сетевого namespace. $1 — рабочая папка.
W=$1
O=$W/out; mkdir -p "$O" "$W/lib"; chmod 777 "$O"; chmod 755 "$W/lib"
PY=$(command -v python3)
NOBODY=$(id -u nobody)
PASS=0; FAILS=0
ok() { echo "ok   - $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL - $1${2:+: $2}"; FAILS=$((FAILS+1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "ожидалось [$3], получено [$2]"; fi; }

# Хелпер без изменений, кроме путей и пользователя
sed -e "s|^LIB=.*|LIB=$W/lib|" -e "s|^RUN=.*|RUN=$W/run|" -e "s|^STATE=.*|STATE=$W/state|" \
    -e "s|^RUNUSER=.*|RUNUSER=nobody|" "$W/byedpi-tg-tun" > "$W/helper"
chmod 755 "$W/helper"
H="$W/helper"

# Заглушка ciadpi: слушает порт из -p, запоминает аргументы и uid
cat > "$W/lib/ciadpi" <<STUB
#!/bin/sh
port=""; prev=""
for a; do [ "\$prev" = -p ] && port=\$a; prev=\$a; done
printf '%s\n' "\$*" > $O/ciadpi_args; id -u > $O/ciadpi_uid
[ -e $O/ciadpi_die ] && { echo "ciadpi: invalid option" >&2; exit 1; }
$PY -c 'import socket,sys,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(); time.sleep(3600)' "\$port" &
c=\$!
trap 'kill \$c; exit 0' TERM INT
wait
STUB
# Заглушка hev-socks5-tunnel: поднимает byedpi0 и пишет в лог всё, что туда пришло
cat > "$W/lib/hev-socks5-tunnel" <<STUB
#!/bin/sh
cp "\$1" $O/hev.yml
[ -e $O/hev_die ] && { echo "socks5 tunnel open (Device busy)" >&2; exit 1; }
$PY $W/tunlog.py byedpi0 $O/tun.log 198.18.0.1/32 &
c=\$!
trap 'kill \$c; exit 0' TERM INT
wait
STUB
chmod 755 "$W/lib/ciadpi" "$W/lib/hev-socks5-tunnel"

# «Интернет»: wan0 с адресом 10.9.0.1/24 и маршрутом по умолчанию, всё ушедшее туда — в лог
ip link set lo up
$PY "$W/tunlog.py" wan0 "$O/wan.log" 10.9.0.1/24 & WANPID=$!
i=0; while ! ip link show wan0 2>/dev/null | grep -q UP && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
ip route add default dev wan0
snap() { ip -4 rule show; ip -4 route show table all | grep -v ' table local'; iptables -w -S; ip link show | grep -c byedpi0; }
base=$(snap)

where() {  # куда ушёл SYN или датаграмма: tun, wan, оба или никуда
    : > "$O/tun.log" 2>/dev/null; : > "$O/wan.log"
    out=$($PY "$W/probe.py" "$@")
    sleep 0.2
    t=$(grep -c " $2 $3\$" "$O/tun.log" 2>/dev/null); w=$(grep -c " $2 $3\$" "$O/wan.log")
    r=none; [ "${t:-0}" -gt 0 ] && r=tun; [ "$w" -gt 0 ] && r=${r#none}wan
    echo "$r${out:+ $out}"
}

# --- отказы до каких-либо изменений
$H start 80 -- -d1 >/dev/null 2>&1; check "порт ниже 1024 отклонён" $? 1
$H start 'x1' -- -d1 >/dev/null 2>&1; check "порт не число: отказ" $? 1
$H start 1090 -d1 >/dev/null 2>&1; check "без -- отказ" $? 1
$H start 1090 -- -d1 -p 9999 >/dev/null 2>&1; check "чужой -p в стратегии отклонён" $? 1
$H start 1090 -- -d1 --transparent >/dev/null 2>&1; check "--transparent отклонён" $? 1
$H start 1090 -- "$(printf -- '-d1\nx')" >/dev/null 2>&1; check "перевод строки в аргументе отклонён" $? 1
check "после отказов ничего не изменилось" "$(snap)" "$base"
setpriv --reuid=$NOBODY --regid=$NOBODY --clear-groups "$H" stop >/dev/null 2>"$O/err"; rc=$?
check "без root отказ" "$rc $(cat "$O/err")" "1 Нужны права root."

# --- ciadpi не запустился: откат
touch "$O/ciadpi_die"
$H start 1090 -- -d1 >/dev/null 2>"$O/err"; rc=$?
check "ciadpi упал: отказ" "$rc" 1
grep -q "invalid option" "$O/err" && ok "ошибка ciadpi показана" || bad "ошибка ciadpi показана" "$(cat "$O/err")"
check "ciadpi упал: ничего не осталось" "$(snap)" "$base"
rm "$O/ciadpi_die"

# --- hev не запустился: откат, включая ciadpi
touch "$O/hev_die"
$H start 1090 -- -d1 >/dev/null 2>"$O/err"; rc=$?
check "туннель не поднялся: отказ" "$rc" 1
grep -q "Device busy" "$O/err" && ok "ошибка hev показана" || bad "ошибка hev показана" "$(cat "$O/err")"
check "туннель не поднялся: ничего не осталось" "$(snap)" "$base"
check "туннель не поднялся: ciadpi остановлен" "$(pgrep -c -f 'lib/ciadpi')" 0
rm "$O/hev_die"

# --- запуск
$H start 1090 -- -d1 -H:youtube.com\ discord.com -An -s1 >"$O/err" 2>&1; rc=$?
[ $rc = 0 ] || echo "# $(cat "$O/err")"; check "запуск" $rc 0
check "ciadpi без root" "$(cat "$O/ciadpi_uid")" "$NOBODY"
check "ciadpi получил порт и стратегию" "$(cat "$O/ciadpi_args")" "-i 127.0.0.1 -p 1090 -d1 -H:youtube.com discord.com -An -s1"
grep -q "port: 1090" "$O/hev.yml" && ok "hev смотрит на порт ciadpi" || bad "hev смотрит на порт ciadpi" "$(cat "$O/hev.yml")"
check "rp_filter на byedpi0 нестрогий" "$(cat /proc/sys/net/ipv4/conf/byedpi0/rp_filter)" 2
$H status >/dev/null; check "status=0" $? 0
check "состояние читается" "$(grep -E '^(port|dev|quic)=' "$W/state" | cut -d= -f2 | tr '\n' ' ')" "1090 byedpi0 block "

# --- куда идёт трафик
check "TCP наружу — в туннель" "$(where tcp 203.0.113.5 80)" tun
check "TCP 443 наружу — в туннель" "$(where tcp 203.0.113.5 443)" tun
check "TCP от пользователя ciadpi — мимо туннеля" "$(where tcp 203.0.113.5 80 $NOBODY)" wan
check "TCP в локальную сеть — мимо туннеля" "$(where tcp 10.9.0.7 80)" wan
check "TCP в Telegram — мимо туннеля" "$(where tcp 149.154.167.51 443)" wan
check "UDP (DNS) — мимо туннеля" "$(where udp 203.0.113.5 53)" "wan sent"
check "QUIC отклонён сразу" "$(where udp 203.0.113.5 443)" "none refused"
ip route add 198.51.100.7 dev wan0
check "адрес с отдельным маршрутом (сервер VPN) — мимо туннеля" "$(where tcp 198.51.100.7 443)" wan
ip route del 198.51.100.7 dev wan0

# --- повторный запуск не плодит правил
$H start 1090 --allow-quic -- -d1 >/dev/null 2>"$O/err"; check "перезапуск" $? 0
check "правило TCP одно" "$(ip -4 rule show pref 2043 | wc -l)" 1
check "без блокировки QUIC" "$(where udp 203.0.113.5 443)" "wan sent"
check "одна копия ciadpi" "$(pgrep -c -f 'lib/ciadpi')" 1

# --- занятый порт
$H stop >/dev/null
$PY -c 'import socket,time; s=socket.socket(); s.bind(("127.0.0.1",1090)); s.listen(); time.sleep(5)' & BUSY=$!
sleep 0.3
$H start 1090 -- -d1 >/dev/null 2>"$O/err"; rc=$?
check "занятый порт: отказ" "$rc" 1
grep -q "занят" "$O/err" && ok "про занятый порт сказано" || bad "про занятый порт сказано" "$(cat "$O/err")"
kill $BUSY; wait $BUSY 2>/dev/null

# --- остановка
$H start 1090 -- -d1 >/dev/null 2>&1
$H stop >/dev/null; check "stop" $? 0
check "после остановки всё как было" "$(snap)" "$base"
check "процессы остановлены" "$(pgrep -c -f 'lib/ciadpi|lib/hev|tun.log')" 0
$H status >/dev/null; check "status после остановки" $? 3
check "TCP после остановки — напрямую" "$(where tcp 203.0.113.5 80)" wan
$H stop >/dev/null; check "повторная остановка" $? 0

kill $WANPID 2>/dev/null
echo "RESULT $([ $FAILS = 0 ] && echo PASS || echo FAIL) ($PASS ok, $FAILS fail)"
