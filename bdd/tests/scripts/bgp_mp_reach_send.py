#!/usr/bin/env python3
"""Minimal scripted BGP speaker announcing IPv4 unicast inside MP_REACH_NLRI.

zebra-rs, FRR and GoBGP all emit plain IPv4 unicast in the traditional
NLRI field, so a router-to-router topology can never produce the RFC 4760
S3 encoding (AFI=1/SAFI=1 reachability inside the MP_REACH_NLRI attribute
with the next-hop carried in the attribute). This script plays that
sender -- the shape xk6-bgp and other MP-first stacks emit -- against a
zebra-rs DUT (issue fixed by PR #2045).

Flow:
  1. TCP-connect to the DUT, send OPEN with capabilities MP(1/1) and
     4-octet AS, answer its OPEN with a KEEPALIVE, wait for its KEEPALIVE.
  2. Send ONE UPDATE whose only reachability is an MP_REACH_NLRI
     attribute (v4 next-hop inside the attribute, no traditional NLRI).
     A decoy NEXT_HOP attribute rides along; per RFC 4760 the MP_REACH
     next-hop must win, so the DUT installing the decoy is a bug the
     feature would catch.
  3. Keep the session alive with keepalives. When TRIGGER_FILE appears
     (touched by a later scenario), send a traditional withdrawn-routes
     UPDATE for the same prefix -- withdraws are prefix-keyed, so mixing
     encodings is legal and proves the MP_REACH-announced route went into
     the ordinary Loc-RIB.
  4. Exit when the peer closes the connection (feature teardown stops the
     DUT). The feature wraps the script in `timeout N` as a backstop.

Usage:
  bgp_mp_reach_send.py DUT_IP LOCAL_AS ROUTER_ID PREFIX MP_NEXTHOP \
      DECOY_NEXTHOP TRIGGER_FILE
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
HOLDTIME = 90


def bgp_msg(msg_type, body):
    return MARKER + struct.pack("!HB", 19 + len(body), msg_type) + body


def open_msg(local_as, router_id):
    caps = bytes([CAP_MP, 4]) + struct.pack("!HBB", 1, 0, 1)  # AFI=1/SAFI=1
    caps += bytes([CAP_AS4, 4]) + struct.pack("!I", local_as)
    opt = bytes([2, len(caps)]) + caps  # one Capabilities optional parameter
    my_as2 = local_as if local_as < 65536 else 23456  # AS_TRANS
    body = struct.pack("!BHH4sB", 4, my_as2, HOLDTIME,
                       socket.inet_aton(router_id), len(opt)) + opt
    return bgp_msg(MSG_OPEN, body)


def peer_open_has_as4(body):
    """Scan the OPEN's optional parameters for the 4-octet-AS capability."""
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


def update_announce(local_as, prefix, mp_nexthop, decoy_nexthop, as4):
    attrs = b"\x40\x01\x01\x00"  # ORIGIN = IGP
    fmt = "!BBI" if as4 else "!BBH"
    seg = struct.pack(fmt, 2, 1, local_as)  # one AS_SEQUENCE of local AS
    attrs += bytes([0x40, 2, len(seg)]) + seg  # AS_PATH
    attrs += b"\x40\x03\x04" + socket.inet_aton(decoy_nexthop)  # NEXT_HOP
    val = (struct.pack("!HBB", 1, 1, 4) + socket.inet_aton(mp_nexthop)
           + b"\x00" + nlri_bytes(prefix))  # AFI/SAFI/nhlen/nh/SNPA=0/NLRI
    attrs += bytes([0x80, 14, len(val)]) + val  # MP_REACH_NLRI
    body = struct.pack("!H", 0) + struct.pack("!H", len(attrs)) + attrs
    return bgp_msg(MSG_UPDATE, body)


def update_withdraw(prefix):
    w = nlri_bytes(prefix)
    return bgp_msg(MSG_UPDATE, struct.pack("!H", len(w)) + w + b"\x00\x00")


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


def session(dut_ip, local_as, router_id, prefix, mp_nexthop, decoy, trigger):
    sock = socket.create_connection((dut_ip, 179), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(30)
    sock.sendall(open_msg(local_as, router_id))
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
            break  # Established
        elif msg_type == MSG_NOTIFICATION:
            raise ConnectionError(f"NOTIFICATION in handshake: {body.hex()}")
    print(f"established (peer as4={peer_as4}); announcing {prefix} "
          f"via MP_REACH next-hop {mp_nexthop}", flush=True)
    sock.sendall(update_announce(local_as, prefix, mp_nexthop, decoy, peer_as4))

    sock.settimeout(1)
    last_keepalive = time.time()
    withdrawn = False
    while True:
        try:
            m = read_msg(sock)
            if m is None:
                print("peer closed; exiting", flush=True)
                return
            if m[0] == MSG_NOTIFICATION:
                print(f"NOTIFICATION: {m[1].hex()}; exiting", flush=True)
                return
        except socket.timeout:
            pass
        if time.time() - last_keepalive > 20:
            sock.sendall(bgp_msg(MSG_KEEPALIVE, b""))
            last_keepalive = time.time()
        if not withdrawn and os.path.exists(trigger):
            print(f"trigger file seen; withdrawing {prefix} via the "
                  "traditional withdrawn-routes field", flush=True)
            sock.sendall(update_withdraw(prefix))
            withdrawn = True


def main():
    dut_ip, local_as, router_id, prefix, mp_nexthop, decoy, trigger = (
        sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4],
        sys.argv[5], sys.argv[6], sys.argv[7])
    # A stale trigger from a crashed prior run would withdraw immediately.
    try:
        os.unlink(trigger)
    except FileNotFoundError:
        pass
    # The DUT's neighbor config may not be applied yet when we are spawned
    # (it closes/refuses until then) -- retry the whole handshake.
    deadline = time.time() + 120
    while True:
        try:
            session(dut_ip, local_as, router_id, prefix, mp_nexthop, decoy,
                    trigger)
            return
        except (ConnectionError, OSError) as e:
            if time.time() > deadline:
                print(f"giving up: {e}", file=sys.stderr, flush=True)
                sys.exit(1)
            print(f"session attempt failed ({e}); retrying", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
