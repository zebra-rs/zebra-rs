#!/usr/bin/env python3
"""SSM receiver: source-specific join + received-payload logging.

Usage: ssm_recv.py GROUP SOURCE LOCAL_ADDR PORT OUTFILE

Joins (SOURCE, GROUP) on the interface owning LOCAL_ADDR via
IP_ADD_SOURCE_MEMBERSHIP (the kernel emits an IGMPv3 source-specific
report), then appends every received UDP payload to OUTFILE — the
end-to-end datapath proof for the PIM SSM BDD feature. OUTFILE is
created immediately so pollers can `cat` it before traffic arrives.
"""

import socket
import sys

IP_ADD_SOURCE_MEMBERSHIP = 39

group, source, local, port, outfile = sys.argv[1:6]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((group, int(port)))

# struct ip_mreq_source: imr_multiaddr, imr_interface, imr_sourceaddr.
mreq = (
    socket.inet_aton(group) + socket.inet_aton(local) + socket.inet_aton(source)
)
sock.setsockopt(socket.IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, mreq)

with open(outfile, "w", buffering=1) as out:
    out.write("joined\n")
    while True:
        data, _ = sock.recvfrom(2048)
        out.write(data.decode(errors="replace") + "\n")
