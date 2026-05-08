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

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup IS-IS L2 with MT 2 over a shared bridge and confirm the link is up | |
| MT 2 SPF installs reciprocal IPv6 routes to peer loopbacks | |
| LSPs carry the multi-topology TLVs | |
