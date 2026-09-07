#!/usr/bin/env python3
"""Wire-level check of bulk-withdraw packing and Adj-RIB-Out coherence.

Two scripted iBGP clients of one zebra-rs route reflector, both living in the
feature's h1 namespace on different addresses. The *source* feeds routes and
withdrawals in bursts; the *observer* parses the reflector's raw TCP stream
and checks:

  1. Packing — a burst of 1000 withdrawals per family arrives in a bounded
     number of UPDATEs, each within the negotiated message size.
  2. Coherence — announce+withdraw and withdraw+announce sent back to back
     leave the observer in the right final state (absent / present), i.e. a
     queued withdrawal never overtakes or outlives the announcement it races.

Run as `bgp_withdraw_packing.py <4096|65535>`; the second form negotiates
RFC 8654 extended messages. All sockets are scoped to this process.
"""
import ipaddress
import json
import math
import select
import socket
import struct
import sys
import time

FAMILIES = ((1, 1), (2, 1), (1, 128), (2, 128), (25, 70))
COUNT = 1000
# Routes per input UPDATE. The reflector drains its withdraw queue on a
# next-tick marker that lands behind the ingest already queued, so every
# drain covers at least one whole input UPDATE.
BATCH = 40


def frame(kind, body=b""):
    return b"\xff" * 16 + struct.pack("!HB", len(body) + 19, kind) + body


def attribute(kind, value, flags=0x80):
    if len(value) > 255:
        return struct.pack("!BBH", flags | 0x10, kind, len(value)) + value
    return bytes((flags, kind, len(value))) + value


def open_message(address, maximum):
    caps = b"".join(bytes((1, 4)) + struct.pack("!HBB", afi, 0, safi)
                    for afi, safi in FAMILIES)
    caps += bytes((65, 4)) + struct.pack("!I", 65001)
    if maximum > 4096:
        caps += bytes((6, 0))
    options = bytes((2, len(caps))) + caps
    return frame(1, struct.pack("!BHH4sB", 4, 65001, 90,
                               socket.inet_aton(address), len(options)) + options)


def nlri(family, i):
    v4 = ipaddress.IPv4Address(0x0a640000 + i).packed
    v6 = ipaddress.IPv6Address(int(ipaddress.IPv6Address("2001:db8:100::")) + i).packed
    rd = struct.pack("!HHI", 0, 65001, i % 3 + 1)
    if family == (1, 1):
        return b"\x20" + v4
    if family == (2, 1):
        return b"\x80" + v6
    if family[1] == 128:
        prefix = v4 if family[0] == 1 else v6
        return bytes((88 + len(prefix) * 8,)) + b"\x00\x06\x41" + rd + prefix
    # EVPN Type-5, alternating IPv4/IPv6 to exercise variable wire lengths.
    prefix = v4 if i % 2 == 0 else v6
    value = rd + bytes(10) + bytes(4) + bytes((len(prefix) * 8,))
    value += prefix + bytes(len(prefix)) + b"\x00\x06\x41"
    return bytes((5, len(value))) + value


def route_key(family, raw):
    # Withdrawals reconstruct labels (and EVPN gateways) rather than retaining
    # the announcement's forwarding fields. Compare route identity, not labels.
    if family[1] == 128:
        return raw[:1] + raw[4:]
    if family == (25, 70):
        return raw[:29 if raw[1] == 34 else 41]
    return raw


def entries(family, data):
    result = []
    while data:
        size = 2 + data[1] if family == (25, 70) else 1 + (data[0] + 7) // 8
        assert size <= len(data), "truncated NLRI"
        result.append(route_key(family, data[:size]))
        data = data[size:]
    return result


def update(family, routes, withdraw):
    data = b"".join(routes)
    if withdraw:
        attrs = b"" if family == (1, 1) else attribute(15, struct.pack("!HB", *family) + data)
        withdrawn = data if family == (1, 1) else b""
        tail = b""
    else:
        attrs = attribute(1, b"\x00", 0x40) + attribute(2, b"", 0x40)
        attrs += attribute(5, struct.pack("!I", 100), 0x40)
        withdrawn = b""
        tail = data if family == (1, 1) else b""
        if family == (1, 1):
            attrs += attribute(3, socket.inet_aton("192.0.2.2"), 0x40)
        else:
            nh = ipaddress.ip_address("2001:db8::2" if family[0] == 2 else "192.0.2.2").packed
            if family[1] == 128:
                nh = bytes(8) + nh
            attrs += attribute(14, struct.pack("!HB", *family) + bytes((len(nh),)) + nh + b"\x00" + data)
    return frame(2, struct.pack("!H", len(withdrawn)) + withdrawn
                 + struct.pack("!H", len(attrs)) + attrs + tail)


def burst(family, routes, withdraw):
    """`routes` as a run of BATCH-route UPDATEs, concatenated for one send."""
    return b"".join(update(family, routes[i:i + BATCH], withdraw)
                    for i in range(0, len(routes), BATCH))


def parse_update(body):
    withdrawn_len = struct.unpack("!H", body[:2])[0]
    changes = []
    if withdrawn_len:
        changes.append(((1, 1), True, entries((1, 1), body[2:2 + withdrawn_len])))
    pos = 2 + withdrawn_len
    attrs_len = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2
    end = pos + attrs_len
    assert end <= len(body)
    while pos < end:
        flags, kind = body[pos:pos + 2]
        width = 2 if flags & 0x10 else 1
        length = int.from_bytes(body[pos + 2:pos + 2 + width], "big")
        start = pos + 2 + width
        value = body[start:start + length]
        assert start + length <= end
        pos = start + length
        if kind in (14, 15):
            family = struct.unpack("!HB", value[:3])
            skip = 5 + value[3] if kind == 14 else 3
            changes.append((family, kind == 15, entries(family, value[skip:])))
    if end < len(body):
        changes.append(((1, 1), False, entries((1, 1), body[end:])))
    return changes


class Client:
    def __init__(self, address, maximum):
        self.sock = socket.socket()
        self.sock.settimeout(10)
        self.sock.bind((address, 0))
        self.sock.connect(("192.0.2.1", 179))
        self.sock.sendall(open_message(address, maximum))
        self.buffer = b""
        self.established = False
        self.maximum = maximum

    def receive(self):
        data = self.sock.recv(262144)
        assert data, "session closed unexpectedly"
        self.buffer += data
        changes = []
        while len(self.buffer) >= 19:
            assert self.buffer[:16] == b"\xff" * 16
            length, kind = struct.unpack("!HB", self.buffer[16:19])
            assert 19 <= length <= self.maximum, f"invalid message length {length}"
            if len(self.buffer) < length:
                break
            body, self.buffer = self.buffer[19:length], self.buffer[length:]
            assert kind != 3, f"BGP NOTIFICATION: {body.hex()}"
            if kind == 1:
                # Verify extended negotiation rather than merely assuming it.
                if self.maximum > 4096:
                    assert b"\x06\x00" in body[10:], "DUT did not advertise extended messages"
                self.sock.sendall(frame(4))
            elif kind == 4:
                self.established = True
            elif kind == 2:
                changes.extend(parse_update(body))
        return changes


class Observer:
    """Tracks, per family, the set of routes the reflector currently
    advertises to the observer client, applying UPDATEs in wire order."""

    def __init__(self):
        self.present = {family: set() for family in FAMILIES}
        # Per-family log of (withdrawn?, nlri_count) since the last reset.
        self.log = {family: [] for family in FAMILIES}

    def apply(self, family, withdrawn, keys):
        if family not in self.present:
            return
        if withdrawn:
            self.present[family].difference_update(keys)
        else:
            self.present[family].update(keys)
        self.log[family].append((withdrawn, len(keys)))

    def reset_log(self, family):
        self.log[family] = []


def run(maximum):
    source = Client("192.0.2.2", maximum)
    observer = Client("192.0.2.3", maximum)
    clients = (source, observer)
    state = Observer()
    last_keepalive = time.monotonic()

    def pump(deadline, what):
        nonlocal last_keepalive
        assert time.monotonic() < deadline, f"timed out waiting for {what}"
        if time.monotonic() - last_keepalive > 15:
            for c in clients:
                c.sock.sendall(frame(4))
            last_keepalive = time.monotonic()
        readable, _, _ = select.select([c.sock for c in clients], [], [], 0.2)
        seen = False
        for c in clients:
            if c.sock in readable:
                for family, withdrawn, keys in c.receive():
                    if c is observer:
                        state.apply(family, withdrawn, keys)
                        seen = True
        return seen

    def wait_until(predicate, what, seconds=30):
        deadline = time.monotonic() + seconds
        while not predicate():
            pump(deadline, what)

    def settle(seconds=2.0, limit=60):
        """Pump until the observer has been quiet for `seconds`."""
        deadline = time.monotonic() + limit
        quiet_since = time.monotonic()
        while time.monotonic() - quiet_since < seconds:
            if pump(deadline, "quiescence"):
                quiet_since = time.monotonic()

    try:
        wait_until(lambda: all(c.established for c in clients), "sessions")
        results = []
        for family in FAMILIES:
            routes = [nlri(family, i) for i in range(COUNT)]
            expected = {route_key(family, r) for r in routes}
            present = state.present[family]

            # ── 1. Packing: announce, wait for every route, withdraw in a burst.
            source.sock.sendall(burst(family, routes, False))
            wait_until(lambda: present == expected, f"{family} announcements")
            assert present <= expected, "unexpected reflected route"
            state.reset_log(family)
            source.sock.sendall(burst(family, routes, True))
            wait_until(lambda: not present, f"{family} withdrawals")
            log = state.log[family]
            assert all(withdrawn for withdrawn, _ in log), \
                f"{family}: a stale announcement overtook a withdrawal: {log}"
            assert all(n > 0 for _, n in log), "unexpected EoR during withdrawals"
            sizes = [n for _, n in log]
            assert sum(sizes) == COUNT
            # Bound: each drain covers at least one whole input UPDATE, so at
            # most COUNT/BATCH drains, each spilling at most one packet's worth
            # of NLRI to the next packet; a second COUNT/BATCH of slack covers
            # a drain replayed behind an in-flight announce job.
            wire = [len(route_key(family, r)) + (3 if family[1] == 128 else 0) for r in routes]
            overhead = 23 if family == (1, 1) else 30
            per_packet = maximum - overhead - max(wire)
            bound = 2 * math.ceil(COUNT / BATCH) + math.ceil(sum(wire) / per_packet)
            assert len(sizes) <= bound, \
                f"{family}: {COUNT} withdrawals took {len(sizes)} UPDATEs, bound {bound}"
            assert max(sizes) > 1, f"{family}: all withdrawals were singleton UPDATEs"
            results.append(dict(family=family, withdrawn=COUNT, messages=len(sizes),
                                largest_nlri_count=max(sizes), bound=bound))
            print(f"PASS {family}: {COUNT} withdrawals in {len(sizes)} UPDATEs "
                  f"(bound {bound}), largest {max(sizes)} NLRIs", flush=True)

            # ── 2. Coherence: announce+withdraw back to back ⇒ absent.
            state.reset_log(family)
            source.sock.sendall(burst(family, routes, False) + burst(family, routes, True))
            settle()
            assert not present, \
                f"{family}: {len(present)} routes survived announce+withdraw"
            print(f"PASS {family}: announce+withdraw burst settles absent "
                  f"({len(state.log[family])} UPDATEs seen)", flush=True)

            # ── 3. Coherence: withdraw+announce back to back ⇒ present.
            source.sock.sendall(burst(family, routes, False))
            wait_until(lambda: present == expected, f"{family} re-announcements")
            state.reset_log(family)
            source.sock.sendall(burst(family, routes, True) + burst(family, routes, False))
            settle()
            assert present == expected, \
                f"{family}: {len(expected - present)} routes lost across withdraw+announce"
            print(f"PASS {family}: withdraw+announce burst settles present "
                  f"({len(state.log[family])} UPDATEs seen)", flush=True)

            # ── 4. Clean up for the next family.
            source.sock.sendall(burst(family, routes, True))
            wait_until(lambda: not present, f"{family} final withdrawals")

        # A final KEEPALIVE exchange verifies the parser/session survived all
        # of it. The sockets remain open until every assertion completes.
        for c in clients:
            c.sock.sendall(frame(4))
        settle(1.0)
        assert not any(state.present.values()), "late route change after completion"
        print(json.dumps(results), flush=True)
        # The harness discards stdout; leave the numbers where a human can
        # read them after the run.
        with open(f"/tmp/bgp_withdraw_packing-{maximum}.json", "w") as f:
            f.write(json.dumps(results, indent=2) + "\n")
    finally:
        for c in clients:
            c.sock.close()


if __name__ == "__main__":
    maximum = int(sys.argv[1])
    assert maximum in (4096, 65535)
    run(maximum)
