#!/usr/bin/env python3
"""Minimal scripted BGP speaker for the RFC 4760 MP-encoded IPv4 unicast forms.

zebra-rs, FRR and GoBGP all put plain IPv4 unicast in the traditional
NLRI / Withdrawn Routes fields, so a router-to-router topology can never
produce the RFC 4760 encodings for AFI=1/SAFI=1 -- reachability inside
MP_REACH_NLRI (S3) and withdrawals inside MP_UNREACH_NLRI (S4). This
script plays that sender, the shape xk6-bgp and other MP-first stacks
emit. Both encodings were broken in zebra-rs: MP_REACH was accepted and
silently dropped (fixed by PR #2045), MP_UNREACH failed to parse and
reset the session.

Flow:
  1. TCP-connect to the DUT, send OPEN with capabilities MP(1/1) and
     4-octet AS, answer its OPEN with a KEEPALIVE, wait for its KEEPALIVE.
  2. Announce PREFIX in an MP_REACH_NLRI attribute (v4 next-hop inside
     the attribute, no traditional NLRI). A decoy NEXT_HOP attribute
     rides along; per RFC 4760 the MP_REACH next-hop must win, so a DUT
     installing the decoy is a bug the feature would catch.
  3. Keep the session alive with keepalives and act on trigger files,
     each consumed (unlinked) when it fires so re-touching re-triggers:
       <TRIGGER_BASE>.announce               re-announce via MP_REACH
       <TRIGGER_BASE>.withdraw_traditional   withdraw via the legacy
                                             Withdrawn Routes field
       <TRIGGER_BASE>.withdraw_mp            withdraw via MP_UNREACH
     Mixing encodings is deliberate: a traditional withdraw of an
     MP_REACH-announced prefix only works if the route went into the
     ordinary Loc-RIB rather than a side path.
  4. Exit when the peer closes the connection (feature teardown stops the
     DUT). The feature wraps the script in `timeout N` as a backstop.

Usage:
  bgp_mp_reach_send.py DUT_IP LOCAL_AS ROUTER_ID PREFIX MP_NEXTHOP \
      DECOY_NEXTHOP TRIGGER_BASE
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
ATTR_MP_REACH, ATTR_MP_UNREACH = 14, 15
AFI_IP, SAFI_UNICAST = 1, 1
HOLDTIME = 90
TRIGGERS = ("announce", "withdraw_traditional", "withdraw_mp")


def bgp_msg(msg_type, body):
    return MARKER + struct.pack("!HB", 19 + len(body), msg_type) + body


def open_msg(local_as, router_id):
    caps = bytes([CAP_MP, 4]) + struct.pack("!HBB", AFI_IP, 0, SAFI_UNICAST)
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
    """Prefix length octet + the ceil(plen/8) significant prefix octets."""
    net = ipaddress.ip_network(prefix)
    nbytes = (net.prefixlen + 7) // 8
    return bytes([net.prefixlen]) + net.network_address.packed[:nbytes]


def attr(flags, type_code, value):
    return bytes([flags, type_code, len(value)]) + value


def update_msg(withdrawn, attrs, nlri=b""):
    body = (struct.pack("!H", len(withdrawn)) + withdrawn
            + struct.pack("!H", len(attrs)) + attrs + nlri)
    return bgp_msg(MSG_UPDATE, body)


def update_announce(local_as, prefix, mp_nexthop, decoy_nexthop, as4):
    attrs = attr(0x40, 1, b"\x00")  # ORIGIN = IGP
    fmt = "!BBI" if as4 else "!BBH"
    attrs += attr(0x40, 2, struct.pack(fmt, 2, 1, local_as))  # AS_PATH
    attrs += attr(0x40, 3, socket.inet_aton(decoy_nexthop))  # NEXT_HOP
    # MP_REACH: AFI/SAFI, next-hop length + address, SNPA=0, NLRI.
    value = (struct.pack("!HBB", AFI_IP, SAFI_UNICAST, 4)
             + socket.inet_aton(mp_nexthop) + b"\x00" + nlri_bytes(prefix))
    attrs += attr(0x80, ATTR_MP_REACH, value)
    return update_msg(b"", attrs)


def update_withdraw_traditional(prefix):
    return update_msg(nlri_bytes(prefix), b"")


def update_withdraw_mp(prefix):
    """RFC 4760 §4 withdrawal: MP_UNREACH is the UPDATE's only attribute.

    A withdraw-only UPDATE carries no mandatory path attributes, so this
    is exactly what an MP-first sender puts on the wire.
    """
    value = struct.pack("!HB", AFI_IP, SAFI_UNICAST) + nlri_bytes(prefix)
    return update_msg(b"", attr(0x80, ATTR_MP_UNREACH, value))


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


def clear_triggers(base):
    """Drop stale trigger files so a crashed prior run cannot fire one."""
    for name in TRIGGERS:
        try:
            os.unlink(f"{base}.{name}")
        except FileNotFoundError:
            pass


def take_trigger(base):
    """Return the name of one fired trigger, consuming it, else None."""
    for name in TRIGGERS:
        path = f"{base}.{name}"
        if os.path.exists(path):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            return name
    return None


def session(dut_ip, local_as, router_id, prefix, mp_nexthop, decoy, base):
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
    announce = update_announce(local_as, prefix, mp_nexthop, decoy, peer_as4)
    print(f"established (peer as4={peer_as4}); announcing {prefix} "
          f"via MP_REACH next-hop {mp_nexthop}", flush=True)
    sock.sendall(announce)

    sock.settimeout(1)
    last_keepalive = time.time()
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
        fired = take_trigger(base)
        if fired == "announce":
            print(f"re-announcing {prefix} via MP_REACH", flush=True)
            sock.sendall(announce)
        elif fired == "withdraw_traditional":
            print(f"withdrawing {prefix} via the traditional "
                  "withdrawn-routes field", flush=True)
            sock.sendall(update_withdraw_traditional(prefix))
        elif fired == "withdraw_mp":
            print(f"withdrawing {prefix} via MP_UNREACH", flush=True)
            sock.sendall(update_withdraw_mp(prefix))


def main():
    dut_ip, local_as, router_id, prefix, mp_nexthop, decoy, base = (
        sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4],
        sys.argv[5], sys.argv[6], sys.argv[7])
    clear_triggers(base)
    # The DUT's neighbor config may not be applied yet when we are spawned
    # (it closes/refuses until then) -- retry the whole handshake.
    deadline = time.time() + 120
    while True:
        try:
            session(dut_ip, local_as, router_id, prefix, mp_nexthop, decoy,
                    base)
            return
        except (ConnectionError, OSError) as e:
            if time.time() > deadline:
                print(f"giving up: {e}", file=sys.stderr, flush=True)
                sys.exit(1)
            print(f"session attempt failed ({e}); retrying", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
