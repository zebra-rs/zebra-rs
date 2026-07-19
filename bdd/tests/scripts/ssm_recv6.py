#!/usr/bin/env python3
"""IPv6 SSM receiver: source-specific join + received-payload logging.

Usage: ssm_recv6.py GROUP SOURCE IFNAME PORT OUTFILE

Joins (SOURCE, GROUP) on interface IFNAME via MCAST_JOIN_SOURCE_GROUP
(the kernel emits an MLDv2 source-specific report), then appends every
received UDP payload to OUTFILE — the end-to-end datapath proof for the
PIMv6 SSM BDD feature. OUTFILE is created immediately so pollers can
`cat` it before traffic arrives.
"""

import socket
import struct
import sys

MCAST_JOIN_SOURCE_GROUP = 46

group, source, ifname, port, outfile = sys.argv[1:6]
ifindex = socket.if_nametoindex(ifname)

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((group, int(port)))


def sockaddr_in6(addr):
    """A `struct sockaddr_in6` padded out to `sockaddr_storage` (128 B)."""
    # sin6_family, sin6_port, sin6_flowinfo, sin6_addr[16], sin6_scope_id
    sa = struct.pack(
        "HHI16sI",
        socket.AF_INET6,
        0,
        0,
        socket.inet_pton(socket.AF_INET6, addr),
        0,
    )
    return sa + b"\x00" * (128 - len(sa))


# struct group_source_req { uint32_t gsr_interface; sockaddr_storage
# gsr_group; sockaddr_storage gsr_source; } — the storage members are
# 8-byte aligned, so 4 bytes of padding follow gsr_interface.
req = (
    struct.pack("I", ifindex)
    + b"\x00" * 4
    + sockaddr_in6(group)
    + sockaddr_in6(source)
)
sock.setsockopt(socket.IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, req)

with open(outfile, "w", buffering=1) as out:
    out.write("joined\n")
    while True:
        data, _ = sock.recvfrom(2048)
        out.write(data.decode(errors="replace") + "\n")
