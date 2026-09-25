#!/usr/bin/env python3
"""Scripted BGP speaker that churns one prefix inside a single MRAI window.

Review finding #15 (update-group advertise-cache desync): a prefix whose
attributes change and which is then withdrawn, all inside one
advertisement interval of the DUT, was re-announced at the flush under
its FIRST attributes -- `send_ipv4` / `send_ipv6` inserted it into the new
attribute bucket without evicting it from the old one, and the withdraw
purged only the new bucket. The DUT's Adj-RIB-Out no longer held the
prefix, so no later withdraw could ever reach the downstream peer. A real
router cannot reliably produce three UPDATEs for one prefix inside a few
milliseconds; this script can.

Flow:
  1. TCP-connect to the DUT, send OPEN with MP(AFI/1) and 4-octet AS,
     answer its OPEN with a KEEPALIVE, wait for its KEEPALIVE.
  2. Announce the warm-up prefix W at once. Its only job is to get the
     DUT to resolve NEXTHOP: a next-hop the DUT has never tracked starts
     out unreachable until NHT answers, so a burst sent before that would
     never reach the advertise path at all (an empty selection) and the
     feature would pass vacuously. The feature waits for W downstream
     before firing the burst.
  3. Keep the session alive and wait for the trigger file
     <TRIGGER_BASE>.burst. When it appears (consumed on firing), send in
     ONE write:
       announce P  (ORIGIN IGP)
       announce P  (ORIGIN INCOMPLETE)   -- an attribute change
       withdraw P
       announce Q  (ORIGIN IGP)          -- the control: flushed in the
                                            same MRAI window as P's churn
     Q reaching the downstream peer proves the flush happened; P must not.
  4. Exit when the peer closes the connection.

AFI 4 uses the traditional NLRI / Withdrawn Routes fields with a NEXT_HOP
attribute; AFI 6 uses MP_REACH_NLRI / MP_UNREACH_NLRI (AFI 2, SAFI 1).

Usage:
  bgp_attr_churn_send.py DUT_IP LOCAL_AS ROUTER_ID AFI PREFIX_W PREFIX_P \
      PREFIX_Q NEXTHOP TRIGGER_BASE
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
SAFI_UNICAST = 1
ORIGIN_IGP, ORIGIN_INCOMPLETE = 0, 2
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


def update_msg(withdrawn, attrs, nlri=b""):
    body = (struct.pack("!H", len(withdrawn)) + withdrawn
            + struct.pack("!H", len(attrs)) + attrs + nlri)
    return bgp_msg(MSG_UPDATE, body)


def announce(afi, local_as, prefix, nexthop, origin, as4):
    attrs = attr(0x40, 1, bytes([origin]))
    fmt = "!BBI" if as4 else "!BBH"
    attrs += attr(0x40, 2, struct.pack(fmt, 2, 1, local_as))
    if afi == 4:
        attrs += attr(0x40, 3, socket.inet_aton(nexthop))
        return update_msg(b"", attrs, nlri_bytes(prefix))
    nh = ipaddress.IPv6Address(nexthop).packed
    value = (struct.pack("!HBB", 2, SAFI_UNICAST, len(nh)) + nh + b"\x00"
             + nlri_bytes(prefix))
    attrs += attr(0x80, ATTR_MP_REACH, value)
    return update_msg(b"", attrs)


def withdraw(afi, prefix):
    if afi == 4:
        return update_msg(nlri_bytes(prefix), b"")
    value = struct.pack("!HB", 2, SAFI_UNICAST) + nlri_bytes(prefix)
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


def take_trigger(path):
    if os.path.exists(path):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return True
    return False


def session(dut_ip, local_as, router_id, afi, w, p, q, nexthop, trigger):
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
    print(f"established (peer as4={peer_as4}); announcing warm-up {w}; "
          f"waiting for {trigger}", flush=True)
    sock.sendall(announce(afi, local_as, w, nexthop, ORIGIN_IGP, peer_as4))

    burst = (announce(afi, local_as, p, nexthop, ORIGIN_IGP, peer_as4)
             + announce(afi, local_as, p, nexthop, ORIGIN_INCOMPLETE, peer_as4)
             + withdraw(afi, p)
             + announce(afi, local_as, q, nexthop, ORIGIN_IGP, peer_as4))

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
        if take_trigger(trigger):
            print(f"burst: announce {p} (IGP), announce {p} (INCOMPLETE), "
                  f"withdraw {p}, announce {q}", flush=True)
            sock.sendall(burst)


def main():
    (dut_ip, local_as, router_id, afi, w, p, q, nexthop, base) = (
        sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]),
        sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8], sys.argv[9])
    trigger = f"{base}.burst"
    try:
        os.unlink(trigger)
    except FileNotFoundError:
        pass
    deadline = time.time() + 120
    while True:
        try:
            session(dut_ip, local_as, router_id, afi, w, p, q, nexthop,
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
