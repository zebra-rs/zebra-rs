#!/usr/bin/env python3
"""Minimal scripted BGP speaker that announces Flow Specification rules.

zebra-rs has no local flow-spec origination, so a feature that needs flow
specs on the wire has this script play the sender (RFC 8955 / RFC 8956,
SAFI 133). It announces three destination-prefix rules, each in its own
UPDATE so each can carry its own communities:

  rule 3   <net>.3   COMMUNITIES NO_ADVERTISE
  rule 2   <net>.2   COMMUNITIES NO_EXPORT
  rule 1   <net>.1   (none)

in that order, so a receiver that holds rule 1 has also processed the other
two. IPv4 rules are 10.27.N.0/24, IPv6 rules 2001:db8:27:N::/64.

Flow:
  1. TCP-connect to the DUT, send OPEN with capabilities MP(AFI/133) and
     4-octet AS, answer its OPEN with a KEEPALIVE, wait for its KEEPALIVE.
  2. Announce the three rules.
  3. Keep the session alive and act on trigger files, each consumed when it
     fires:
       <TRIGGER_BASE>.noadv1   re-announce rule 1 with NO_ADVERTISE
  4. Exit when the peer closes the connection. The feature wraps the
     script in `timeout N` as a backstop.

With IBGP set the speaker is an internal neighbor: its rules carry an
empty AS_PATH and LOCAL_PREF, so a receiver validating per RFC 9117 finds
them originated inside its AS.

Usage:
  bgp_flowspec_send.py DUT_IP LOCAL_AS ROUTER_ID AFI(4|6) TRIGGER_BASE [ibgp]
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
ATTR_ORIGIN, ATTR_AS_PATH, ATTR_LOCAL_PREF = 1, 2, 5
ATTR_COMMUNITIES, ATTR_MP_REACH = 8, 14
SAFI_FLOWSPEC = 133
NO_EXPORT, NO_ADVERTISE = 0xFFFFFF01, 0xFFFFFF02
HOLDTIME = 90
TRIGGERS = ("noadv1",)


def bgp_msg(msg_type, body):
    return MARKER + struct.pack("!HB", 19 + len(body), msg_type) + body


def open_msg(local_as, router_id, afi):
    caps = bytes([CAP_MP, 4]) + struct.pack("!HBB", afi, 0, SAFI_FLOWSPEC)
    caps += bytes([CAP_AS4, 4]) + struct.pack("!I", local_as)
    opt = bytes([2, len(caps)]) + caps
    my_as2 = local_as if local_as < 65536 else 23456  # AS_TRANS
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


def rule_prefix(afi, n):
    if afi == 1:
        return ipaddress.ip_network(f"10.27.{n}.0/24")
    return ipaddress.ip_network(f"2001:db8:27:{n}::/64")


def flowspec_nlri(afi, n):
    """One rule: a Destination Prefix component (type 1). IPv6 carries an
    offset octet before the pattern (RFC 8956 §3.1)."""
    net = rule_prefix(afi, n)
    nbytes = (net.prefixlen + 7) // 8
    if afi == 1:
        comp = bytes([1, net.prefixlen]) + net.network_address.packed[:nbytes]
    else:
        comp = (bytes([1, net.prefixlen, 0])
                + net.network_address.packed[:nbytes])
    return bytes([len(comp)]) + comp


def attr(flags, type_code, value):
    if len(value) > 255:
        return struct.pack("!BBH", flags | 0x10, type_code, len(value)) + value
    return bytes([flags, type_code, len(value)]) + value


def update_announce(local_as, afi, n, communities, as4, ibgp):
    attrs = attr(0x40, ATTR_ORIGIN, b"\x00")  # IGP
    if ibgp:
        attrs += attr(0x40, ATTR_AS_PATH, b"")  # originated here
        attrs += attr(0x40, ATTR_LOCAL_PREF, struct.pack("!I", 100))
    else:
        fmt = "!BBI" if as4 else "!BBH"
        attrs += attr(0x40, ATTR_AS_PATH, struct.pack(fmt, 2, 1, local_as))
    if communities:
        attrs += attr(0xC0, ATTR_COMMUNITIES,
                      b"".join(struct.pack("!I", c) for c in communities))
    # MP_REACH: AFI / SAFI 133, no next-hop (RFC 8955 §4), SNPA 0, NLRI.
    value = struct.pack("!HBBB", afi, SAFI_FLOWSPEC, 0, 0) + flowspec_nlri(afi, n)
    attrs += attr(0x80, ATTR_MP_REACH, value)
    body = struct.pack("!H", 0) + struct.pack("!H", len(attrs)) + attrs
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


def clear_triggers(base):
    for name in TRIGGERS:
        try:
            os.unlink(f"{base}.{name}")
        except FileNotFoundError:
            pass


def take_trigger(base):
    for name in TRIGGERS:
        path = f"{base}.{name}"
        if os.path.exists(path):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            return name
    return None


def session(dut_ip, local_as, router_id, afi, base, ibgp):
    sock = socket.create_connection((dut_ip, 179), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(30)
    sock.sendall(open_msg(local_as, router_id, afi))
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
    print(f"established (peer as4={peer_as4}); announcing rules 3, 2, 1",
          flush=True)
    for n, communities in ((3, [NO_ADVERTISE]), (2, [NO_EXPORT]), (1, [])):
        sock.sendall(update_announce(local_as, afi, n, communities, peer_as4,
                                     ibgp))

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
        if take_trigger(base) == "noadv1":
            print("re-announcing rule 1 with NO_ADVERTISE", flush=True)
            sock.sendall(update_announce(local_as, afi, 1, [NO_ADVERTISE],
                                         peer_as4, ibgp))


def main():
    dut_ip, local_as, router_id, afi_arg, base = (
        sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5])
    afi = 1 if afi_arg == "4" else 2
    ibgp = len(sys.argv) > 6 and sys.argv[6] == "ibgp"
    clear_triggers(base)
    # The DUT's neighbor config may not be applied yet when we are spawned
    # (it closes/refuses until then) -- retry the whole handshake.
    deadline = time.time() + 120
    while True:
        try:
            session(dut_ip, local_as, router_id, afi, base, ibgp)
            return
        except (ConnectionError, OSError) as e:
            if time.time() > deadline:
                print(f"giving up: {e}", file=sys.stderr, flush=True)
                sys.exit(1)
            print(f"session attempt failed ({e}); retrying", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
