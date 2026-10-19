#!/usr/bin/env python3
"""Minimal scripted iBGP speaker that announces EVPN Type-5 (IP Prefix) routes
carrying a non-zero ESI and Gateway IP.

RFC 9136 §3.1 puts an ESI and a Gateway IP in every Type-5 NLRI; either one,
when non-zero, is the overlay index a remote PE may resolve the prefix
through (§3.2; IP aliasing builds on the ESI form). zebra-rs originates
interface-less Type-5 routes only (both fields zero), so no zebra-rs peer can
produce the route a reflector has to pass on unchanged. This script plays
that sender.

Flow:
  1. TCP-connect to the DUT, send OPEN with capabilities MP(25/70) and
     4-octet AS, answer its OPEN with a KEEPALIVE, wait for its KEEPALIVE.
  2. Announce every ROUTE in one MP_REACH_NLRI (L2VPN/EVPN, IPv4 next hop
     NEXTHOP), with ORIGIN, an empty AS_PATH, LOCAL_PREF 100 and the route
     target LOCAL_AS:100. RD is NEXTHOP:100, Ethernet Tag 0, label 100.
  3. Keep the session alive with keepalives until the peer closes it
     (feature teardown stops the DUT). The feature wraps the script in
     `timeout N` as a backstop.

Each ROUTE is PREFIX[,ESI[,GATEWAY]]: ESI in colon hex, default all zero;
GATEWAY of the prefix's family, default the unspecified address.

Options, before the positional arguments, add forwarding attributes to every
route, as a remote PE's symmetric-IRB or SRv6 Type-5 carries them:
  --rmac MAC        a Router's MAC extended community (RFC 9135 §8.1)
  --vxlan-encap     a BGP Encapsulation extended community, VXLAN (RFC 9012)
  --srv6-sid SID    a Prefix-SID attribute with an SRv6 L3 Service TLV
                    carrying SID as End.DT46 (RFC 9252 §2)

Usage:
  bgp_evpn_type5_send.py [OPTIONS] DUT_IP LOCAL_AS ROUTER_ID NEXTHOP ROUTE...
"""

import ipaddress
import socket
import struct
import sys
import time

MARKER = b"\xff" * 16
MSG_OPEN, MSG_UPDATE, MSG_NOTIFICATION, MSG_KEEPALIVE = 1, 2, 3, 4
CAP_MP, CAP_AS4 = 1, 65
ATTR_MP_REACH = 14
ATTR_PREFIX_SID = 40
SRV6_BEHAVIOR_END_DT46 = 0x0014
TUNNEL_TYPE_VXLAN = 8
AFI_L2VPN, SAFI_EVPN = 25, 70
EVPN_IP_PREFIX = 5
HOLDTIME = 90


def bgp_msg(msg_type, body):
    return MARKER + struct.pack("!HB", 19 + len(body), msg_type) + body


def open_msg(local_as, router_id):
    caps = bytes([CAP_MP, 4]) + struct.pack("!HBB", AFI_L2VPN, 0, SAFI_EVPN)
    caps += bytes([CAP_AS4, 4]) + struct.pack("!I", local_as)
    opt = bytes([2, len(caps)]) + caps  # one Capabilities optional parameter
    my_as2 = local_as if local_as < 65536 else 23456  # AS_TRANS
    body = struct.pack("!BHH4sB", 4, my_as2, HOLDTIME,
                       socket.inet_aton(router_id), len(opt)) + opt
    return bgp_msg(MSG_OPEN, body)


def attr(flags, type_code, value):
    if len(value) > 255:
        return (bytes([flags | 0x10, type_code])
                + struct.pack("!H", len(value)) + value)
    return bytes([flags, type_code, len(value)]) + value


def parse_route(spec):
    parts = spec.split(",")
    net = ipaddress.ip_network(parts[0])
    esi = bytes(10)
    if len(parts) > 1 and parts[1]:
        esi = bytes.fromhex(parts[1].replace(":", ""))
        assert len(esi) == 10, f"ESI must be 10 octets: {parts[1]}"
    gw = ipaddress.ip_address("::" if net.version == 6 else "0.0.0.0")
    if len(parts) > 2 and parts[2]:
        gw = ipaddress.ip_address(parts[2])
        assert gw.version == net.version, f"gateway family: {spec}"
    return net, esi, gw


def type5_nlri(rd, net, esi, gw, label):
    """RFC 9136 §3.1: RD, ESI, Ethernet Tag, IP prefix length, IP prefix and
    Gateway IP at the family's full width, then a 3-octet label."""
    value = (rd + esi + struct.pack("!I", 0) + bytes([net.prefixlen])
             + net.network_address.packed + gw.packed
             + label.to_bytes(3, "big"))
    return bytes([EVPN_IP_PREFIX, len(value)]) + value


def prefix_sid_srv6_l3(sid):
    """RFC 9252: an SRv6 L3 Service TLV holding one SRv6 SID Information
    Sub-TLV (SID, flags 0, End.DT46) with a SID Structure Sub-Sub-TLV
    (locator block 32, node 16, function 16)."""
    structure = bytes([1]) + struct.pack("!H", 6) + bytes([32, 16, 16, 0, 0, 0])
    info = (b"\x00" + ipaddress.IPv6Address(sid).packed + b"\x00"
            + struct.pack("!H", SRV6_BEHAVIOR_END_DT46) + b"\x00" + structure)
    sub_tlv = bytes([1]) + struct.pack("!H", len(info)) + info
    tlv_value = b"\x00" + sub_tlv
    return bytes([5]) + struct.pack("!H", len(tlv_value)) + tlv_value


def update_announce(local_as, nexthop, routes, opts):
    # RD type 1: IPv4 administrator NEXTHOP, assigned number 100.
    rd = struct.pack("!H", 1) + socket.inet_aton(nexthop) + struct.pack("!H", 100)
    nlri = b"".join(type5_nlri(rd, net, esi, gw, 100) for net, esi, gw in routes)
    attrs = attr(0x40, 1, b"\x00")  # ORIGIN = IGP
    attrs += attr(0x40, 2, b"")  # AS_PATH, empty on iBGP
    attrs += attr(0x40, 5, struct.pack("!I", 100))  # LOCAL_PREF
    # Two-octet-AS Route Target LOCAL_AS:100 (RFC 4360 type 0x00/0x02).
    ecom = struct.pack("!BBHI", 0x00, 0x02, local_as, 100)
    if opts.get("vxlan_encap"):
        ecom += struct.pack("!BBIH", 0x03, 0x0C, 0, TUNNEL_TYPE_VXLAN)
    if opts.get("rmac"):
        ecom += bytes([0x06, 0x03]) + bytes.fromhex(opts["rmac"].replace(":", ""))
    attrs += attr(0xC0, 16, ecom)
    if opts.get("srv6_sid"):
        attrs += attr(0xC0, ATTR_PREFIX_SID, prefix_sid_srv6_l3(opts["srv6_sid"]))
    value = (struct.pack("!HBB", AFI_L2VPN, SAFI_EVPN, 4)
             + socket.inet_aton(nexthop) + b"\x00" + nlri)
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


def session(dut_ip, local_as, router_id, nexthop, routes, opts):
    sock = socket.create_connection((dut_ip, 179), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(30)
    sock.sendall(open_msg(local_as, router_id))
    got_open = False
    while True:
        m = read_msg(sock)
        if m is None:
            raise ConnectionError("peer closed during handshake")
        msg_type, body = m
        if msg_type == MSG_OPEN:
            got_open = True
            sock.sendall(bgp_msg(MSG_KEEPALIVE, b""))
        elif msg_type == MSG_KEEPALIVE and got_open:
            break  # Established
        elif msg_type == MSG_NOTIFICATION:
            raise ConnectionError(f"NOTIFICATION in handshake: {body.hex()}")
    print(f"established; announcing {len(routes)} Type-5 route(s) "
          f"via next hop {nexthop}", flush=True)
    sock.sendall(update_announce(local_as, nexthop, routes, opts))

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


def main():
    args, opts = sys.argv[1:], {}
    while args and args[0].startswith("--"):
        flag = args.pop(0)
        if flag == "--vxlan-encap":
            opts["vxlan_encap"] = True
        elif flag in ("--rmac", "--srv6-sid"):
            opts[flag[2:].replace("-", "_")] = args.pop(0)
        else:
            sys.exit(f"unknown option {flag}")
    dut_ip, local_as, router_id, nexthop = (
        args[0], int(args[1]), args[2], args[3])
    routes = [parse_route(spec) for spec in args[4:]]
    # The DUT's neighbor config may not be applied yet when we are spawned
    # (it closes/refuses until then) -- retry the whole handshake.
    deadline = time.time() + 120
    while True:
        try:
            session(dut_ip, local_as, router_id, nexthop, routes, opts)
            return
        except (ConnectionError, OSError) as e:
            if time.time() > deadline:
                print(f"giving up: {e}", file=sys.stderr, flush=True)
                sys.exit(1)
            print(f"session attempt failed ({e}); retrying", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
