# IS-IS SRv6 End.X (adjacency) SID is gated on the neighbor's IPv6

## Overview

As a network operator
I want an SRv6 End.X adjacency SID to be allocated only for a neighbor that
can actually forward IPv6 — one that advertises the IPv6 NLPID in its
Protocols Supported TLV AND gives us an IPv6 link-local nexthop — and I want
that decision re-evaluated as the neighbor's capability changes, so enabling
IPv6 on an already-Up adjacency starts advertising an End.X without a flap.

## Test Topology

```
   x1 ───────────────── x2
   i2  10.0.12.0/30      i1
       2001:db8:12::/64
   lo 10.0.0.1/32        lo 10.0.0.2/32
   SRv6 locator LX1
   (fcbb:1::/64)
```

## Notes

x1 runs SRv6 with a classic locator, so it owns an End SID and would carve
an End.X for each IPv6-capable adjacency. The x1–x2 IS-IS circuit starts
IPv4-only (IS-IS `ipv4 enable` only), so x2 advertises no IPv6 and x1 must
NOT allocate an End.X for it. A later scenario enables IPv6 on the circuit;
x2 then advertises IPv6 and x1 allocates the End.X by re-evaluation.
This also pins the `show segment-routing srv6 sid` column rename: the owner
column is "Protocol" and the value is "isis" (no instance suffix).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the topology — an IPv4-only neighbor gets no End.X SID | |
| Enabling IPv6 on the neighbor re-evaluates and allocates the End.X SID | |
| Teardown topology | |
