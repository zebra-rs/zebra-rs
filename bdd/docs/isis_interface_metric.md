# IS-IS connected-prefix reachability reflects the interface metric

## Overview

As a network operator
I want the IS-IS interface `metric` to apply not only to the IS
reachability (adjacency cost) but also to the IPv4 (TLV 135) and
IPv6 (TLV 236) reachability advertised for that interface's connected
prefixes, so a non-default interface metric raises the advertised cost
of the attached subnets the same way FRR / IOS-XR do — rather than a
fixed metric 10 regardless of configuration.

## Test Topology

```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
        10.0.1.1/24        10.0.1.2/24
     2001:db8:1::1/64   2001:db8:1::2/64
            (vz1ns)             (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          └─────────┘     └─────────┘
   lo: 10.0.0.1/32          lo: 10.0.0.2/32
   2001:db8:0:ffff::1/128   2001:db8:0:ffff::2/128
```

## Notes

Both configs set `metric 55` on the vzXns interface (a non-default
value; the default is 10). The connected prefixes 10.0.1.0/24 and
2001:db8:1::/64 must therefore appear in the LSPs with Metric 55.
The loopbacks leave `metric` unset, so they stay at the default 10 —
a built-in contrast that proves the metric is applied per interface.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup dual-stack IS-IS L2 with a non-default interface metric | |
| IPv4 connected prefix (TLV 135) carries the interface metric | |
| IPv6 connected prefix (TLV 236) carries the interface metric | |
| The loopback prefixes keep the default metric 10 | |
| Teardown topology | |
