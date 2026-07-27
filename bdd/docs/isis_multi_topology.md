# IS-IS multi-topology (RFC 5120)

## Overview

As a network operator
I want two zebra-rs instances to participate in IS-IS multi-topology
routing for IPv6 unicast (MT 2), exchanging TLV 229 / 222 / 237 in
their LSPs and installing IPv6 reachability through the per-MT SPF
result, so dual-stack networks can run independent IPv4 and IPv6
topologies.

## Test Topology

```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
       2001:db8:1::1/64   2001:db8:1::2/64
            (vz1ns)             (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          │ +MT 2   │     │ +MT 2   │
          └─────────┘     └─────────┘
   lo: 2001:db8:0:ffff::1   lo: 2001:db8:0:ffff::2
              /128                  /128
```

## Notes

Both configs add `multi-topology ipv6-unicast;` under `router/isis/`
so the LSPs carry TLV 229 (capability), TLV 222 (MT IS Reach), and
TLV 237 (MT IPv6 Reach).
Both vzXns interfaces set a base `metric 55` and a per-MT override
`multi-topology ipv6-unicast metric 77`. Because IPv6 rides MT 2, the
connected prefix 2001:db8:1::/64 must be advertised in TLV 237 with the
per-MT metric 77 — not the base 55 and not a fixed 10. The loopback
leaves both unset, so it falls all the way back to the default 10: a
built-in check of the per-MT → base → default fallback chain.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup IS-IS L2 with MT 2 over a shared bridge and confirm the link is up | |
| MT 2 SPF installs reciprocal IPv6 routes to peer loopbacks | |
| LSPs carry the multi-topology TLVs | |
| MT IPv6 Reachability carries the per-MT interface metric | |
| MT metric falls back to the default for an interface without an override | |
| Teardown topology | |
