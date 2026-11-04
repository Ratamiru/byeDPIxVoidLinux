#!/usr/bin/env python3
"""udp_probe.py send <ip> <port> <n> <hex|discord|stun> | recv <port> <секунды>"""
import socket
import sys
import time

PAYLOADS = {
    "discord": bytes([0, 1, 0, 70, 1, 2, 3, 4]) + bytes(66),
    "stun": bytes([0, 1, 0, 0, 0x21, 0x12, 0xA4, 0x42]) + bytes(12),
    "other": b"\xaa" * 64,
}
if sys.argv[1] == "send":
    ip, port, n, kind = sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ip, port))
    for _ in range(n):
        s.send(PAYLOADS[kind])
        time.sleep(0.005)
else:
    port, secs = int(sys.argv[2]), float(sys.argv[3])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    s.settimeout(0.2)
    end, sizes = time.time() + secs, {}
    while time.time() < end:
        try:
            data = s.recv(4096)
        except TimeoutError:
            continue
        sizes[len(data)] = sizes.get(len(data), 0) + 1
    print(" ".join(f"{k}:{v}" for k, v in sorted(sizes.items())) or "none")
