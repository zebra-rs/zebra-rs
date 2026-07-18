#!/usr/bin/env python3
"""Multicast UDP sender for BDD datapath tests.

Usage: mcast_send.py GROUP PORT LOCAL_ADDR COUNT

Sends one small datagram per second to GROUP:PORT from the interface
owning LOCAL_ADDR, TTL 8 so it survives a router hop or two.
"""

import socket
import sys
import time

group, port, local, count = sys.argv[1:5]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 8)

for _ in range(int(count)):
    sock.sendto(b"ssm-hello", (group, int(port)))
    time.sleep(1)
