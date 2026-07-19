#!/usr/bin/env python3
"""IPv6 ASM (any-source) receiver: join + received-payload logging.

Usage: asm_recv6.py GROUP IFNAME PORT OUTFILE

Joins GROUP on interface IFNAME via IPV6_JOIN_GROUP (the kernel emits an
MLDv2 EXCLUDE{} report to ff02::16), then appends every received UDP
payload to OUTFILE — the end-to-end proof for the PIMv6 ASM BDD feature.
OUTFILE is created immediately so pollers can `cat` it before traffic
arrives.
"""

import socket
import struct
import sys

group, ifname, port, outfile = sys.argv[1:5]
ifindex = socket.if_nametoindex(ifname)

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((group, int(port)))

# struct ipv6_mreq { struct in6_addr ipv6mr_multiaddr; unsigned int
# ipv6mr_interface; }
mreq = socket.inet_pton(socket.AF_INET6, group) + struct.pack("@I", ifindex)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

with open(outfile, "w", buffering=1) as out:
    out.write("joined\n")
    while True:
        data, _ = sock.recvfrom(2048)
        out.write(data.decode(errors="replace") + "\n")
