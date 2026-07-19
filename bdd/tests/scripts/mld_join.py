#!/usr/bin/env python3
"""MLD group joiner: join an IPv6 multicast group on an interface so
the kernel emits an MLDv2 report, then hold the membership open.

Usage: mld_join.py <group> <ifname> <seconds>

Joining with IPV6_JOIN_GROUP triggers the kernel's MLDv2 EXCLUDE
report to ff02::16; the router's MLD querier learns the group.
"""
import socket
import struct
import sys
import time

group_str, ifname, seconds = sys.argv[1], sys.argv[2], int(sys.argv[3])
ifindex = socket.if_nametoindex(ifname)

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
group = socket.inet_pton(socket.AF_INET6, group_str)
# struct ipv6_mreq { in6_addr multiaddr; unsigned int ifindex; }
mreq = group + struct.pack("@I", ifindex)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

time.sleep(seconds)
