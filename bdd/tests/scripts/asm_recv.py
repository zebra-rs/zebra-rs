#!/usr/bin/env python3
"""ASM (any-source) receiver: IP_ADD_MEMBERSHIP join + payload log.

Usage: asm_recv.py GROUP LOCAL_ADDR PORT OUTFILE

Joins GROUP on the interface owning LOCAL_ADDR (the kernel emits an
IGMPv3 EXCLUDE{} report), then appends every received UDP payload to
OUTFILE — the end-to-end proof for the PIM ASM BDD feature. OUTFILE
is created immediately so pollers can `cat` it before traffic
arrives.
"""

import socket
import sys

group, local, port, outfile = sys.argv[1:5]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((group, int(port)))

mreq = socket.inet_aton(group) + socket.inet_aton(local)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

with open(outfile, "w", buffering=1) as out:
    out.write("joined\n")
    while True:
        data, _ = sock.recvfrom(2048)
        out.write(data.decode(errors="replace") + "\n")
