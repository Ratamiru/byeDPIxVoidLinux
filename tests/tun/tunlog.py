#!/usr/bin/env python3
"""Поднимает tun-интерфейс и пишет в лог каждый пришедший в него IPv4-пакет: «tcp ОТКУДА КУДА ПОРТ»."""
import fcntl
import os
import struct
import subprocess
import sys

TUNSETIFF, IFF_TUN, IFF_NO_PI = 0x400454CA, 0x0001, 0x1000
name, log = sys.argv[1], sys.argv[2]
fd = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))
for addr in sys.argv[3:]:
    subprocess.run(["ip", "addr", "add", addr, "dev", name], check=True)
subprocess.run(["ip", "link", "set", name, "up"], check=True)
with open(log, "a", buffering=1) as f:
    while True:
        p = os.read(fd, 65535)
        if not p or p[0] >> 4 != 4:
            continue
        ihl = (p[0] & 15) * 4
        proto = {6: "tcp", 17: "udp"}.get(p[9], str(p[9]))
        dport = int.from_bytes(p[ihl + 2:ihl + 4], "big") if proto in ("tcp", "udp") else 0
        src, dst = ".".join(map(str, p[12:16])), ".".join(map(str, p[16:20]))
        f.write(f"{proto} {src} {dst} {dport}\n")
