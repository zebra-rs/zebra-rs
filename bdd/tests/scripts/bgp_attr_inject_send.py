#!/usr/bin/env python3
"""Scripted BGP speaker that announces prefixes carrying raw path attributes.

Some path attributes can only reach the DUT from a speaker that breaks
the rules: every real router strips ORIGINATOR_ID and CLUSTER_LIST on
eBGP egress, and none emits a 3-octet ORIGINATOR_ID. This script puts
arbitrary attribute TLVs on otherwise ordinary announcements so a feature
can pin how the DUT ingests them.

Flow:
  1. TCP-connect to the DUT, send OPEN with MP(AFI/1) and 4-octet AS,
     answer its OPEN with a KEEPALIVE, wait for its KEEPALIVE.
  2. Announce every SPEC given before the "--" separator, one UPDATE per
     prefix, in one write.
  3. Keep the session alive and wait for the trigger file
     <TRIGGER_BASE>.go. When it appears (consumed on firing), announce
     every SPEC given after the separator, in one write.
  4. Exit when the peer closes the connection or sends a NOTIFICATION
     (the NOTIFICATION's code/sub-code is printed first).

SPEC is PREFIX[@ASN,ASN...][=ATTR[+ATTR...]]. The optional @ list is the
AS_PATH, one AS_SEQUENCE left to right (default: LOCAL_AS alone), so a
feature can send a path whose first AS is not the speaker's. ATTR is
FLAGS:TYPE:VALUE with FLAGS and TYPE in hex and VALUE a (possibly empty)
hex string. Each ATTR is appended verbatim after ORIGIN (IGP) / AS_PATH
/ NEXT_HOP, so its length octet is whatever VALUE's length is -- a
malformed attribute is written exactly as given. Examples: an
ORIGINATOR_ID of 192.0.2.1 is 80:09:c0000201; 10.0.0.0/24@65099,65003
announces 10.0.0.0/24 with AS_PATH "65099 65003".

AFI 4 uses the traditional NLRI field with a NEXT_HOP attribute; AFI 6
uses MP_REACH_NLRI (AFI 2, SAFI 1) with NEXTHOP as the global next-hop.

Usage:
  bgp_attr_inject_send.py DUT_IP LOCAL_AS ROUTER_ID AFI NEXTHOP \
      TRIGGER_BASE SPEC... [-- SPEC...]
"""

import ipaddress
import os
import socket
import struct
import sys
import time

MARKER = b"\xff" * 16
MSG_OPEN, MSG_UPDATE, MSG_NOTIFICATION, MSG_KEEPALIVE = 1, 2, 3, 4
CAP_MP, CAP_AS4 = 1, 65
ATTR_MP_REACH = 14
SAFI_UNICAST = 1
ORIGIN_IGP = 0
HOLDTIME = 90


def bgp_msg(msg_type, body):
    return MARKER + struct.pack("!HB", 19 + len(body), msg_type) + body


def open_msg(local_as, router_id, afi):
    caps = bytes([CAP_MP, 4]) + struct.pack("!HBB", afi, 0, SAFI_UNICAST)
    caps += bytes([CAP_AS4, 4]) + struct.pack("!I", local_as)
    opt = bytes([2, len(caps)]) + caps
    my_as2 = local_as if local_as < 65536 else 23456
    body = struct.pack("!BHH4sB", 4, my_as2, HOLDTIME,
                       socket.inet_aton(router_id), len(opt)) + opt
    return bgp_msg(MSG_OPEN, body)


def peer_open_has_as4(body):
    opt_len = body[9]
    opts = body[10:10 + opt_len]
    while len(opts) >= 2:
        ptype, plen = opts[0], opts[1]
        pval, opts = opts[2:2 + plen], opts[2 + plen:]
        if ptype != 2:
            continue
        while len(pval) >= 2:
            code, clen = pval[0], pval[1]
            if code == CAP_AS4:
                return True
            pval = pval[2 + clen:]
    return False


def nlri_bytes(prefix):
    net = ipaddress.ip_network(prefix)
    nbytes = (net.prefixlen + 7) // 8
    return bytes([net.prefixlen]) + net.network_address.packed[:nbytes]


def attr(flags, type_code, value):
    return bytes([flags, type_code, len(value)]) + value


def parse_spec(spec):
    """PREFIX[@ASN,...][=FLAGS:TYPE:VALUE[+...]] ->
    (prefix, AS_PATH list or None, raw attribute bytes)."""
    head, _, rest = spec.partition("=")
    prefix, _, path = head.partition("@")
    aspath = [int(a) for a in path.split(",")] if path else None
    raw = b""
    for item in filter(None, rest.split("+")):
        flags, type_code, value = item.split(":")
        raw += attr(int(flags, 16), int(type_code, 16), bytes.fromhex(value))
    return prefix, aspath, raw


def announce(afi, local_as, prefix, aspath, nexthop, extra, as4):
    attrs = attr(0x40, 1, bytes([ORIGIN_IGP]))
    path = aspath or [local_as]
    fmt = "!" + ("I" if as4 else "H") * len(path)
    attrs += attr(0x40, 2, struct.pack("!BB", 2, len(path))
                  + struct.pack(fmt, *path))
    nlri = b""
    if afi == 4:
        attrs += attr(0x40, 3, socket.inet_aton(nexthop))
        nlri = nlri_bytes(prefix)
    else:
        nh = ipaddress.IPv6Address(nexthop).packed
        value = (struct.pack("!HBB", 2, SAFI_UNICAST, len(nh)) + nh
                 + b"\x00" + nlri_bytes(prefix))
        attrs += attr(0x80, ATTR_MP_REACH, value)
    attrs += extra
    body = (struct.pack("!H", 0) + struct.pack("!H", len(attrs)) + attrs
            + nlri)
    return bgp_msg(MSG_UPDATE, body)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_msg(sock):
    hdr = recv_exact(sock, 19)
    if hdr is None:
        return None
    length, msg_type = struct.unpack("!HB", hdr[16:19])
    body = recv_exact(sock, length - 19) if length > 19 else b""
    if length > 19 and body is None:
        return None
    return msg_type, body


def take_trigger(path):
    if os.path.exists(path):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return True
    return False


def batch(afi, local_as, nexthop, specs, as4):
    out = b""
    for prefix, aspath, extra in specs:
        out += announce(afi, local_as, prefix, aspath, nexthop, extra, as4)
    return out


def session(dut_ip, local_as, router_id, afi, nexthop, trigger, now, later):
    sock = socket.create_connection((dut_ip, 179), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(30)
    sock.sendall(open_msg(local_as, router_id, 1 if afi == 4 else 2))
    peer_as4 = False
    got_open = False
    while True:
        m = read_msg(sock)
        if m is None:
            raise ConnectionError("peer closed during handshake")
        msg_type, body = m
        if msg_type == MSG_OPEN:
            peer_as4 = peer_open_has_as4(body)
            got_open = True
            sock.sendall(bgp_msg(MSG_KEEPALIVE, b""))
        elif msg_type == MSG_KEEPALIVE and got_open:
            break
        elif msg_type == MSG_NOTIFICATION:
            raise ConnectionError(f"NOTIFICATION in handshake: {body.hex()}")
    print(f"established (peer as4={peer_as4}); announcing "
          f"{[p for p, _, _ in now]}; waiting for {trigger}", flush=True)
    sock.sendall(batch(afi, local_as, nexthop, now, peer_as4))

    sock.settimeout(1)
    last_keepalive = time.time()
    while True:
        try:
            m = read_msg(sock)
            if m is None:
                print("peer closed; exiting", flush=True)
                return
            if m[0] == MSG_NOTIFICATION:
                code, sub = (m[1] + b"\x00\x00")[:2]
                print(f"NOTIFICATION code {code} sub-code {sub} "
                      f"({m[1].hex()}); exiting", flush=True)
                return
        except socket.timeout:
            pass
        if time.time() - last_keepalive > 20:
            sock.sendall(bgp_msg(MSG_KEEPALIVE, b""))
            last_keepalive = time.time()
        if take_trigger(trigger):
            print(f"trigger: announcing {[p for p, _, _ in later]}",
                  flush=True)
            sock.sendall(batch(afi, local_as, nexthop, later, peer_as4))


def main():
    (dut_ip, local_as, router_id, afi, nexthop, base) = (
        sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]),
        sys.argv[5], sys.argv[6])
    specs = sys.argv[7:]
    split = specs.index("--") if "--" in specs else len(specs)
    now = [parse_spec(s) for s in specs[:split]]
    later = [parse_spec(s) for s in specs[split + 1:]]
    trigger = f"{base}.go"
    try:
        os.unlink(trigger)
    except FileNotFoundError:
        pass
    deadline = time.time() + 120
    while True:
        try:
            session(dut_ip, local_as, router_id, afi, nexthop, trigger, now,
                    later)
            return
        except (ConnectionError, OSError) as e:
            if time.time() > deadline:
                print(f"giving up: {e}", file=sys.stderr, flush=True)
                sys.exit(1)
            print(f"session attempt failed ({e}); retrying", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
