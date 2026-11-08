#!/usr/bin/env python3
"""probe.py tcp|udp IP PORT [uid|-] [gid] — шлёт один SYN или датаграмму; для UDP печатает refused/sent."""
import os
import socket
import sys
import time

kind, ip, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
if len(sys.argv) > 5:
    os.setgroups([])
    os.setgid(int(sys.argv[5]))
if len(sys.argv) > 4 and sys.argv[4] != "-":
    os.setgid(int(sys.argv[4]))
    os.setuid(int(sys.argv[4]))
if kind == "tcp":
    s = socket.socket()
    s.setblocking(False)
    s.connect_ex((ip, port))
    time.sleep(0.4)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ip, port))
    s.settimeout(0.5)
    try:
        s.send(b"x")
        s.recv(10)
        print("answer")
    except (ConnectionRefusedError, PermissionError):  # REJECT в OUTPUT отвечает EPERM сразу на send
        print("refused")
    except (socket.timeout, OSError):
        print("sent")
