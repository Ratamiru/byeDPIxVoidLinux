#!/bin/sh
# Проверяет voice/byedpi-tg-voice под настоящим root в одноразовой виртуальной машине без сети.
# Хост не затрагивается: корень смонтирован только для чтения, правила живут внутри гостя.
#   tests/vm/run.sh              — со встроенной заглушкой вместо nfqws
#   NFQWS=путь/к/nfqws tests/vm/run.sh  — ещё и с настоящим nfqws
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
KVER="${KVER:-$(uname -r)}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/share"
cp "$HERE/../../voice/byedpi-tg-voice" "$HERE/inside.sh" "$HERE/udp_probe.py" "$WORK/share/"
[ -n "${NFQWS:-}" ] && cp "$NFQWS" "$WORK/share/nfqws.real"
python3 "$HERE/mkinitramfs.py" "$KVER" "$WORK/initramfs.cpio"
ACCEL=tcg; [ -w /dev/kvm ] && ACCEL=kvm
timeout 240 qemu-system-x86_64 -accel "$ACCEL" -m 1024 -smp 2 -nographic -no-reboot -nic none \
    -kernel "/boot/vmlinuz-$KVER" -initrd "$WORK/initramfs.cpio" \
    -append "console=ttyS0 quiet panic=-1 rdinit=/init" \
    -virtfs "local,path=/,mount_tag=hostroot,readonly=on,security_model=none,multidevs=remap" \
    -virtfs "local,path=$WORK/share,mount_tag=share,security_model=none" \
    | tee "$WORK/out.txt" | grep -E --line-buffered '^(ok|FAIL|RESULT|#)'
grep -q '^RESULT PASS' "$WORK/out.txt"
