#!/usr/bin/env python3
"""Собирает минимальный initramfs: busybox и модули для монтирования корня хоста через 9p."""
import ctypes
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT_MODULES = ["virtio_pci", "9pnet_virtio", "9p"]
INIT = """#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sys /sys
/bin/busybox mount -t devtmpfs dev /dev
for m in $(/bin/busybox cat /modules.order); do /bin/busybox insmod /mods/$m; done
/bin/busybox mkdir -p /host
/bin/busybox mount -t 9p -o trans=virtio,version=9p2000.L,ro,cache=loose hostroot /host
for d in proc sys dev; do /bin/busybox mount --bind /$d /host/$d; done
/bin/busybox mount -t tmpfs tmpfs /host/run
/bin/busybox mount -t tmpfs tmpfs /host/tmp
/bin/busybox mkdir -p /host/tmp/share
/bin/busybox mount -t 9p -o trans=virtio,version=9p2000.L share /host/tmp/share
/bin/busybox chroot /host /bin/sh /tmp/share/inside.sh
/bin/busybox poweroff -f
"""


def decompress(data: bytes) -> bytes:
    zstd = ctypes.CDLL("libzstd.so.1")
    zstd.ZSTD_decompress.restype = ctypes.c_size_t
    cap = 64 * 1024 * 1024
    out = ctypes.create_string_buffer(cap)
    n = zstd.ZSTD_decompress(out, ctypes.c_size_t(cap), data, ctypes.c_size_t(len(data)))
    return out.raw[:n]


def write_cpio(root: Path, target: str) -> None:
    """Архив newc: busybox в разных сборках не всегда умеет cpio -o."""
    def entry(f, name: bytes, mode: int, data: bytes, ino: int):
        name += b"\0"
        head = b"070701" + b"".join(b"%08X" % v for v in (
            ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0))
        f.write(head + name)
        f.write(b"\0" * (-(len(head) + len(name)) % 4))
        f.write(data)
        f.write(b"\0" * (-len(data) % 4))

    with open(target, "wb") as f:
        for ino, path in enumerate(sorted(root.rglob("*")), 1):
            st = path.lstat()
            data = b"" if path.is_dir() else path.read_bytes()
            entry(f, str(path.relative_to(root)).encode(), st.st_mode, data, ino)
        entry(f, b"TRAILER!!!", 0, b"", 0)


def main():
    kver, target = sys.argv[1], sys.argv[2]
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for sub in ("bin", "proc", "sys", "dev", "mods"):
            (root / sub).mkdir()
        shutil.copy("/usr/bin/busybox.static", root / "bin/busybox")
        init = root / "init"
        init.write_text(INIT)
        init.chmod(init.stat().st_mode | stat.S_IEXEC)
        order = []
        for mod in ROOT_MODULES:
            out = subprocess.run(["modprobe", "-S", kver, "--show-depends", mod], capture_output=True,
                                 text=True, check=True).stdout
            for line in out.splitlines():
                if not line.startswith("insmod "):
                    continue
                path = Path(line.split()[1])
                name = path.name.split(".ko")[0] + ".ko"
                if name in order:
                    continue
                raw = path.read_bytes()
                (root / "mods" / name).write_bytes(decompress(raw) if path.suffix == ".zst" else raw)
                order.append(name)
        (root / "modules.order").write_text("\n".join(order) + "\n")
        write_cpio(root, target)
    if os.path.getsize(target) < 1024 * 1024:
        sys.exit("initramfs не собрался")


if __name__ == "__main__":
    main()
