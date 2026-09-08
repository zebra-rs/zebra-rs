#!/usr/bin/env python3
"""Scripted eBGP speaker that announces prefixes WITH a LOCAL_PREF attribute.

RFC 4271 S5.1.5: LOCAL_PREF MUST NOT be included in UPDATEs sent to an
external peer, and if it is received from one it MUST be ignored (RFC 7606
S7.6 keeps that as attribute-discard). Every real router strips it on eBGP
egress -- zebra-rs, FRR and GoBGP alike -- so a router-to-router topology
can never put a LOCAL_PREF-bearing eBGP UPDATE in front of the DUT. This
script plays that sender (a buggy or hostile neighbor): it announces the
given prefixes with ORIGIN, AS_PATH, a next-hop and LOCAL_PREF=<value>.
IPv4 prefixes ride the traditional NLRI field with a NEXT_HOP attribute;
IPv6 prefixes ride MP_REACH_NLRI (AFI=2/SAFI=1, RFC 2545) with the
next-hop inside the attribute, and the OPEN advertises the matching
MP capability. All prefixes of one run must share a family.

Flow:
  1. TCP-connect to the DUT, send OPEN with capabilities MP(1/1) and
     4-octet AS, answer its OPEN with a KEEPALIVE, wait for its KEEPALIVE.
  2. Announce every PREFIX in one UPDATE carrying LOCAL_PREF.
  3. Keep the session alive with keepalives and act on trigger files,
     each consumed (unlinked) when it fires so re-touching re-triggers:
       <TRIGGER_BASE>.announce   re-announce the prefixes (same attrs)
       <TRIGGER_BASE>.withdraw   withdraw them (Withdrawn Routes field for
                                 IPv4, MP_UNREACH_NLRI for IPv6)
  4. Exit when the peer closes the connection (feature teardown stops the
     DUT). The feature wraps the script in `timeout N` as a backstop.

The handshake and message helpers are shared with bgp_mp_reach_send.py
(same directory; python puts the script's own directory first on sys.path).

Usage:
  bgp_ebgp_local_pref_send.py DUT_IP LOCAL_AS ROUTER_ID NEXTHOP LOCAL_PREF \
      TRIGGER_BASE PREFIX [PREFIX ...]
"""

import ipaddress
import os
import socket
import struct
import sys
import time

# The feature runs this under `sudo ip netns exec`; importing the sibling
# module would otherwise drop a root-owned __pycache__ into the repo tree.
sys.dont_write_bytecode = True

from bgp_mp_reach_send import (  # noqa: E402
    ATTR_MP_REACH,
    ATTR_MP_UNREACH,
    CAP_AS4,
    CAP_MP,
    HOLDTIME,
    MSG_KEEPALIVE,
    MSG_NOTIFICATION,
    MSG_OPEN,
    attr,
    bgp_msg,
    nlri_bytes,
    peer_open_has_as4,
    read_msg,
    update_msg,
)

ATTR_ORIGIN, ATTR_AS_PATH, ATTR_NEXT_HOP, ATTR_LOCAL_PREF = 1, 2, 3, 5
AFI_IP, AFI_IP6, SAFI_UNICAST = 1, 2, 1
TRIGGERS = ("announce", "withdraw")


def family_of(prefixes):
    """AFI shared by every prefix (mixing families in one run is an error)."""
    afis = {AFI_IP6 if ipaddress.ip_network(p).version == 6 else AFI_IP
            for p in prefixes}
    if len(afis) != 1:
        raise SystemExit(f"prefixes must share one family: {prefixes}")
    return afis.pop()


def open_msg_for(local_as, router_id, afi):
    """OPEN advertising MP(afi/1) + 4-octet AS (bgp_mp_reach_send's OPEN
    pins AFI=1; the IPv6 run needs AFI=2 negotiated instead)."""
    caps = bytes([CAP_MP, 4]) + struct.pack("!HBB", afi, 0, SAFI_UNICAST)
    caps += bytes([CAP_AS4, 4]) + struct.pack("!I", local_as)
    opt = bytes([2, len(caps)]) + caps  # one Capabilities optional parameter
    my_as2 = local_as if local_as < 65536 else 23456  # AS_TRANS
    body = struct.pack("!BHH4sB", 4, my_as2, HOLDTIME,
                       socket.inet_aton(router_id), len(opt)) + opt
    return bgp_msg(MSG_OPEN, body)


def update_announce(local_as, prefixes, nexthop, local_pref, as4):
    """Announce `prefixes` with a LOCAL_PREF attribute.

    LOCAL_PREF is well-known discretionary (flags 0x40), type code 5,
    4-octet value -- the exact shape an iBGP peer would send. Putting it
    on an eBGP session is the whole point. IPv4 goes in the traditional
    NLRI field with a NEXT_HOP attribute; IPv6 goes in MP_REACH_NLRI with
    the (global) next-hop inside the attribute.
    """
    attrs = attr(0x40, ATTR_ORIGIN, b"\x00")  # ORIGIN = IGP
    fmt = "!BBI" if as4 else "!BBH"
    attrs += attr(0x40, ATTR_AS_PATH, struct.pack(fmt, 2, 1, local_as))
    nlri = b"".join(nlri_bytes(p) for p in prefixes)
    if family_of(prefixes) == AFI_IP6:
        nh = ipaddress.ip_address(nexthop).packed
        value = (struct.pack("!HBB", AFI_IP6, SAFI_UNICAST, len(nh))
                 + nh + b"\x00" + nlri)
        attrs += attr(0x80, ATTR_MP_REACH, value)
        nlri = b""
    else:
        attrs += attr(0x40, ATTR_NEXT_HOP, socket.inet_aton(nexthop))
    # Last so the LOCAL_PREF sits after the mandatory attributes, as a
    # real (iBGP) sender would order it.
    attrs += attr(0x40, ATTR_LOCAL_PREF, struct.pack("!I", local_pref))
    return update_msg(b"", attrs, nlri)


def update_withdraw(prefixes):
    nlri = b"".join(nlri_bytes(p) for p in prefixes)
    if family_of(prefixes) == AFI_IP6:
        value = struct.pack("!HB", AFI_IP6, SAFI_UNICAST) + nlri
        return update_msg(b"", attr(0x80, ATTR_MP_UNREACH, value))
    return update_msg(nlri, b"")


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


def session(dut_ip, local_as, router_id, nexthop, local_pref, base, prefixes):
    sock = socket.create_connection((dut_ip, 179), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(30)
    sock.sendall(open_msg_for(local_as, router_id, family_of(prefixes)))
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
    announce = update_announce(local_as, prefixes, nexthop, local_pref,
                               peer_as4)
    print(f"established (peer as4={peer_as4}); announcing {prefixes} "
          f"next-hop {nexthop} LOCAL_PREF {local_pref}", flush=True)
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
            print(f"re-announcing {prefixes} LOCAL_PREF {local_pref}",
                  flush=True)
            sock.sendall(announce)
        elif fired == "withdraw":
            print(f"withdrawing {prefixes}", flush=True)
            sock.sendall(update_withdraw(prefixes))


def main():
    if len(sys.argv) < 8:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    dut_ip, local_as, router_id, nexthop, local_pref, base = (
        sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4],
        int(sys.argv[5]), sys.argv[6])
    prefixes = sys.argv[7:]
    clear_triggers(base)
    # The DUT's neighbor config may not be applied yet when we are spawned
    # (it closes/refuses until then) -- retry the whole handshake.
    deadline = time.time() + 120
    while True:
        try:
            session(dut_ip, local_as, router_id, nexthop, local_pref, base,
                    prefixes)
            return
        except (ConnectionError, OSError) as e:
            if time.time() > deadline:
                print(f"giving up: {e}", file=sys.stderr, flush=True)
                sys.exit(1)
            print(f"session attempt failed ({e}); retrying", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
