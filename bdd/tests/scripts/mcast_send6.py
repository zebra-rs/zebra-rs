#!/usr/bin/env python3
"""IPv6 multicast UDP sender for BDD datapath tests.

Usage: mcast_send6.py GROUP PORT IFNAME COUNT

Sends one small datagram per second to GROUP:PORT out interface IFNAME,
hop limit 8 so it survives a router hop or two.
"""

import socket
import sys
import time

group, port, ifname, count = sys.argv[1:5]
ifindex = socket.if_nametoindex(ifname)

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 8)

for _ in range(int(count)):
    sock.sendto(b"ssm-hello", (group, int(port)))
    time.sleep(1)
