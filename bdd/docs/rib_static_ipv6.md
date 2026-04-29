# RIB IPv6 static route

## Overview

As a network operator
I want IPv6 static routes to recover after the egress interface goes
Using an isolated test topology with two zebra-rs instances connected

## Test Topology

```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  │                                        │
  └────────────┬───────────────┬───────────┘
               │               │
       2001:db8:1::1/64   2001:db8:1::2/64
            (vz1ns)            (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          └─────────┘     └─────────┘
   lo: 2001:db8:0:ffff::1   lo: 2001:db8:0:ffff::2
              /128                  /128
```

## Config Files

- z1-1.yaml: z1 interface addresses (lo + vz1ns).
- z2-1.yaml: z2 interface addresses (lo + vz2ns).
- z1-2.yaml: static IPv6 route on z1 to z2's loopback via z2's eth0 address.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology for IPv6 loopback and veth address. | |
| Apply IPv6 static route and verify ping to z2's loopback. | |
| Egress interface goes down — static route is invalidated. | |
| Egress interface comes back up — static route recovers. | |
| Bounce egress interface again — recovery is repeatable. | |
