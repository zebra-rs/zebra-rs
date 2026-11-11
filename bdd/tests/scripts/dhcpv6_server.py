#!/usr/bin/env python3
"""A DHCPv6 server that delegates prefixes, for the DHCPv6 client features.

    dhcpv6_server.py TAG start IFACE [--address ADDR] [--pd IAID=PREFIX/LEN]...
                                     [--preferred S] [--valid S] [--t1 S] [--t2 S]
                                     [--dns ADDR] [--route] [--route-also PREFIX/LEN]...
    dhcpv6_server.py TAG stop

dnsmasq, which the other DHCP client features use, leases addresses and
delegates no prefix. This is the part of an ISP's delegating router a
feature needs (RFC 8415), on IFACE of the namespace it runs in:

- `--address` is the one address there is to lease (an IA_NA).
- `--pd IAID=PREFIX` is the prefix delegated to the IA_PD of that IAID.
  Whatever the client hints at, that is what it gets: the server
  decides. An IA_PD under any other IAID is told NoPrefixAvail.
- Lifetimes are `--preferred` and `--valid`; T1 and T2 are half and
  four fifths of the preferred lifetime unless given.
- With `--route` the namespace routes each delegated prefix to the
  client it is delegated to, as a delegating router does, and stops when
  the prefix is given back.
- `--route-also` is a prefix the namespace routes to the client from
  its first lease on, delegated or not: one assigned to the customer by
  other means, which a feature can compare a delegated one with.

It answers Solicit with Advertise, and Request, Renew, Rebind, Confirm,
Release, Decline and Information-request with Reply. A Renew for what it
has no record of is told NoBinding; a Rebind is answered from the
configuration, record or not. `start` returns once the server listens;
it then runs in the background until `stop`.

TAG names the scratch directory, /tmp/zebra-bdd-dhcp/TAG, as for
dhcp_server.sh. Its `server.log` has a line for each message received
and each one sent, which is what a feature reads:

    SOLICIT ia_na 3735928559 ia_pd 1 ::/56
    ADVERTISE 2001:db8:1::100 2001:db8:100::/56
    REQUEST ia_na 3735928559 2001:db8:1::100 ia_pd 1 2001:db8:100::/56
    REPLY 2001:db8:1::100 2001:db8:100::/56
"""
import argparse
import ipaddress
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys

DIR = "/tmp/zebra-bdd-dhcp"
# A DUID-LL (RFC 8415 §11.4) of a made-up Ethernet address.
DUID = bytes.fromhex("000300010200000000fe")

SOLICIT, ADVERTISE, REQUEST, CONFIRM, RENEW, REBIND, REPLY, RELEASE, DECLINE = range(1, 10)
INFORMATION_REQUEST = 11
NAMES = {
    SOLICIT: "SOLICIT",
    REQUEST: "REQUEST",
    CONFIRM: "CONFIRM",
    RENEW: "RENEW",
    REBIND: "REBIND",
    RELEASE: "RELEASE",
    DECLINE: "DECLINE",
    INFORMATION_REQUEST: "INFORMATION-REQUEST",
}

OPT_CLIENTID, OPT_SERVERID, OPT_IA_NA, OPT_IAADDR = 1, 2, 3, 5
OPT_STATUS, OPT_DNS, OPT_IA_PD, OPT_IAPREFIX = 13, 23, 25, 26
SUCCESS, NO_ADDRS_AVAIL, NO_BINDING, NO_PREFIX_AVAIL = 0, 2, 3, 6


def options(data):
    """The options in `data`, as (code, body)."""
    out = []
    while len(data) >= 4:
        code, length = struct.unpack("!HH", data[:4])
        out.append((code, data[4 : 4 + length]))
        data = data[4 + length :]
    return out


def option(code, body):
    return struct.pack("!HH", code, len(body)) + body


def status(code, text):
    return option(OPT_STATUS, struct.pack("!H", code) + text.encode())


class Server:
    def __init__(self, args, sock, ifindex, log):
        self.args = args
        self.sock = sock
        self.ifindex = ifindex
        self.log = log
        self.address = ipaddress.IPv6Address(args.address) if args.address else None
        self.prefixes = {}
        for spec in args.pd:
            iaid, prefix = spec.split("=")
            self.prefixes[int(iaid)] = ipaddress.IPv6Network(prefix)
        self.t1 = args.t1 if args.t1 is not None else args.preferred // 2
        self.t2 = args.t2 if args.t2 is not None else args.preferred * 4 // 5
        # What is leased: ("na" or "pd", IAID) -> the client's DUID.
        self.bound = {}

    def say(self, text):
        self.log.write(text + "\n")
        self.log.flush()

    def route(self, verb, prefix, client):
        command = ["ip", "-6", "route", verb, str(prefix)]
        if verb == "replace":
            # Python names a link-local address with its interface.
            command += ["via", client.split("%")[0], "dev", self.args.iface]
        subprocess.run(command, check=False, stderr=subprocess.DEVNULL)

    def lease(self, kind, key, duid, what):
        """Whether the client `duid` gets `what` under `key`, and why not."""
        if what is None:
            return False
        holder = self.bound.get(key)
        if holder not in (None, duid):
            return False
        if kind == RENEW and holder is None:
            return None
        if kind != SOLICIT:
            self.bound[key] = duid
        return True

    def ia_na(self, kind, duid, iaid, given):
        leased = self.lease(kind, ("na", iaid), duid, self.address)
        if leased is None:
            return struct.pack("!III", iaid, 0, 0) + status(NO_BINDING, "no such lease")
        if not leased:
            return struct.pack("!III", iaid, 0, 0) + status(NO_ADDRS_AVAIL, "none left")
        given.append(str(self.address))
        times = struct.pack("!II", self.args.preferred, self.args.valid)
        addr = option(OPT_IAADDR, self.address.packed + times)
        return struct.pack("!III", iaid, self.t1, self.t2) + addr

    def ia_pd(self, kind, duid, iaid, given, source):
        prefix = self.prefixes.get(iaid)
        leased = self.lease(kind, ("pd", iaid), duid, prefix)
        if leased is None:
            return struct.pack("!III", iaid, 0, 0) + status(NO_BINDING, "no such delegation")
        if not leased:
            return struct.pack("!III", iaid, 0, 0) + status(NO_PREFIX_AVAIL, "none for this IAID")
        given.append(str(prefix))
        if kind != SOLICIT and self.args.route:
            self.route("replace", prefix, source)
        body = struct.pack("!IIB", self.args.preferred, self.args.valid, prefix.prefixlen)
        iaprefix = option(OPT_IAPREFIX, body + prefix.network_address.packed)
        return struct.pack("!III", iaid, self.t1, self.t2) + iaprefix

    def release(self, duid, key):
        if self.bound.get(key) != duid:
            return
        del self.bound[key]
        if key[0] == "pd" and self.args.route:
            self.route("del", self.prefixes[key[1]], None)

    def handle(self, data, source):
        if len(data) < 4 or data[0] not in NAMES:
            return
        kind, xid = data[0], data[1:4]
        asked = options(data[4:])
        duid = next((body for code, body in asked if code == OPT_CLIENTID), None)
        server = next((body for code, body in asked if code == OPT_SERVERID), None)
        # RFC 8415 §16: who a message is for.
        if duid is None and kind != INFORMATION_REQUEST:
            return
        if kind in (REQUEST, RENEW, RELEASE, DECLINE) and server != DUID:
            return
        if kind in (SOLICIT, CONFIRM, REBIND) and server is not None:
            return

        heard = [NAMES[kind]]
        reply = [option(OPT_SERVERID, DUID)]
        if duid is not None:
            reply.append(option(OPT_CLIENTID, duid))
        given = []
        for code, body in asked:
            if code not in (OPT_IA_NA, OPT_IA_PD) or len(body) < 12:
                continue
            iaid = struct.unpack("!I", body[:4])[0]
            inner = options(body[12:])
            if code == OPT_IA_NA:
                heard.append(f"ia_na {iaid}")
                for sub, addr in inner:
                    if sub == OPT_IAADDR and len(addr) >= 16:
                        heard.append(str(ipaddress.IPv6Address(addr[:16])))
                key = ("na", iaid)
            else:
                heard.append(f"ia_pd {iaid}")
                for sub, pfx in inner:
                    if sub == OPT_IAPREFIX and len(pfx) >= 25:
                        heard.append(f"{ipaddress.IPv6Address(pfx[9:25])}/{pfx[8]}")
                key = ("pd", iaid)
            if kind in (RELEASE, DECLINE):
                self.release(duid, key)
            elif kind in (SOLICIT, REQUEST, RENEW, REBIND):
                if code == OPT_IA_NA:
                    reply.append(option(code, self.ia_na(kind, duid, iaid, given)))
                else:
                    reply.append(option(code, self.ia_pd(kind, duid, iaid, given, source[0])))
        self.say(" ".join(heard))
        if kind in (REQUEST, RENEW, REBIND):
            for prefix in self.args.route_also:
                self.route("replace", prefix, source[0])

        if kind == CONFIRM:
            reply.append(status(SUCCESS, "all on link"))
        elif kind in (RELEASE, DECLINE):
            reply.append(status(SUCCESS, "given back"))
        if self.args.dns:
            reply.append(option(OPT_DNS, ipaddress.IPv6Address(self.args.dns).packed))
        answer = ADVERTISE if kind == SOLICIT else REPLY
        message = bytes([answer]) + xid + b"".join(reply)
        try:
            self.sock.sendto(message, source)
        except OSError as e:
            # No link-local through DAD yet, say: the client asks again.
            self.say(f"not sent: {e}")
            return
        self.say(" ".join(["ADVERTISE" if kind == SOLICIT else "REPLY"] + given))

    def run(self):
        while True:
            data, source = self.sock.recvfrom(4096)
            self.handle(data, source)


def start(args):
    scratch = os.path.join(DIR, args.tag)
    os.makedirs(scratch, exist_ok=True)
    ifindex = socket.if_nametoindex(args.iface)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.iface.encode())
    sock.bind(("::", 547))
    # All_DHCP_Relay_Agents_and_Servers.
    group = socket.inet_pton(socket.AF_INET6, "ff02::1:2") + struct.pack("@I", ifindex)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group)

    # Listening: the rest is the background's, and the caller goes on.
    pid = os.fork()
    if pid:
        with open(os.path.join(scratch, "server.pid"), "w") as f:
            f.write(f"{pid}\n")
        return
    os.setsid()
    log = open(os.path.join(scratch, "server.log"), "a")
    null = os.open(os.devnull, os.O_RDWR)
    os.dup2(null, 0)
    os.dup2(log.fileno(), 1)
    os.dup2(log.fileno(), 2)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    Server(args, sock, ifindex, log).run()


def stop(args):
    scratch = os.path.join(DIR, args.tag)
    try:
        with open(os.path.join(scratch, "server.pid")) as f:
            os.kill(int(f.read()), signal.SIGTERM)
    except (OSError, ValueError):
        pass
    shutil.rmtree(scratch, ignore_errors=True)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("tag")
    sub = p.add_subparsers(dest="action", required=True)
    s = sub.add_parser("start")
    s.add_argument("iface")
    s.add_argument("--address")
    s.add_argument("--pd", action="append", default=[])
    s.add_argument("--preferred", type=int, default=3600)
    s.add_argument("--valid", type=int, default=7200)
    s.add_argument("--t1", type=int)
    s.add_argument("--t2", type=int)
    s.add_argument("--dns")
    s.add_argument("--route", action="store_true")
    s.add_argument("--route-also", action="append", default=[])
    sub.add_parser("stop")
    args = p.parse_args()
    if args.action == "start":
        start(args)
    else:
        stop(args)


if __name__ == "__main__":
    main()
