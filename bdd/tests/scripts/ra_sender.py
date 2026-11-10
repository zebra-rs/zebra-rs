#!/usr/bin/env python3
"""Send IPv6 Router Advertisements (RFC 4861) for the RA host features.

    ra_sender.py IFACE [--source LINK-LOCAL] [--lifetime S] [--preference high|medium|low]
                       [--prefix PREFIX/LEN,FLAGS,VALID,PREFERRED]...
                       [--rdnss ADDR,LIFETIME]... [--dnssl DOMAIN,LIFETIME]...
                       [--mtu N] [--count N] [--interval S]

Each RA goes to ff02::1 out IFACE in the namespace this runs in, from
--source when given (a feature pins the router's address that way),
else from a link-local of the kernel's choosing; the script waits up to
10 s for one to finish DAD. FLAGS is any of `L` and `A` (`-` for neither). A lifetime of
`infinity` is 0xffffffff. The router lifetime defaults to 1800 s; 0 tells
hosts this router is no default router any more.

Unlike a router daemon, this sends exactly what it is told, once (or
`--count` times), which is what lets a feature drive lifetimes, flags and
preferences step by step.
"""
import argparse
import ipaddress
import socket
import struct
import sys
import time

INFINITY = 0xFFFFFFFF
PRF = {"high": 0b01, "medium": 0b00, "low": 0b11}


def lifetime(text):
    return INFINITY if text == "infinity" else int(text)


def link_local_ready(iface):
    """Whether IFACE has a link-local that is through DAD."""
    with open("/proc/net/if_inet6") as f:
        for line in f:
            _addr, _idx, _plen, scope, flags, name = line.split()
            # Scope 0x20 is link; IFA_F_TENTATIVE is 0x40.
            if name == iface and int(scope, 16) == 0x20 and not int(flags, 16) & 0x40:
                return True
    return False


def option(typ, body):
    """An ND option: type, length in units of 8 octets, padded body."""
    total = (2 + len(body) + 7) // 8 * 8
    return struct.pack("!BB", typ, total // 8) + body + b"\0" * (total - 2 - len(body))


def prefix_option(spec):
    prefix, flags, valid, preferred = spec.split(",")
    net = ipaddress.IPv6Network(prefix, strict=False)
    bits = (0x80 if "L" in flags else 0) | (0x40 if "A" in flags else 0)
    body = struct.pack(
        "!BBIII16s",
        net.prefixlen,
        bits,
        lifetime(valid),
        lifetime(preferred),
        0,
        net.network_address.packed,
    )
    return option(3, body)


def rdnss_option(spec):
    addr, life = spec.split(",")
    body = struct.pack("!HI", 0, lifetime(life)) + ipaddress.IPv6Address(addr).packed
    return option(25, body)


def dnssl_option(spec):
    domain, life = spec.split(",")
    names = b"".join(
        bytes([len(label)]) + label.encode() for label in domain.split(".") if label
    )
    return option(31, struct.pack("!HI", 0, lifetime(life)) + names + b"\0")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("iface")
    p.add_argument("--source")
    p.add_argument("--lifetime", type=int, default=1800)
    p.add_argument("--preference", choices=PRF, default="medium")
    p.add_argument("--prefix", action="append", default=[])
    p.add_argument("--rdnss", action="append", default=[])
    p.add_argument("--dnssl", action="append", default=[])
    p.add_argument("--mtu", type=int)
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--interval", type=float, default=1.0)
    args = p.parse_args()

    deadline = time.monotonic() + 10
    while not link_local_ready(args.iface):
        if time.monotonic() > deadline:
            sys.exit(f"{args.iface}: no link-local through DAD")
        time.sleep(0.2)

    # Type 134, code 0, checksum (the kernel fills it in on a raw ICMPv6
    # socket), hop limit 64, M/O 0 and the preference, router lifetime,
    # reachable time and retrans timer 0.
    ra = struct.pack("!BBHBBHII", 134, 0, 0, 64, PRF[args.preference] << 3, args.lifetime, 0, 0)
    for spec in args.prefix:
        ra += prefix_option(spec)
    for spec in args.rdnss:
        ra += rdnss_option(spec)
    for spec in args.dnssl:
        ra += dnssl_option(spec)
    if args.mtu is not None:
        ra += option(5, struct.pack("!HI", 0, args.mtu))

    ifindex = socket.if_nametoindex(args.iface)
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    # RFC 4861 §6.1.2: a receiver drops an RA whose hop limit is not 255.
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
    if args.source:
        s.bind((args.source, 0, 0, ifindex))
    for n in range(args.count):
        if n:
            time.sleep(args.interval)
        s.sendto(ra, ("ff02::1", 0, 0, ifindex))
    print(f"sent {args.count} RA(s) on {args.iface}")


if __name__ == "__main__":
    main()
