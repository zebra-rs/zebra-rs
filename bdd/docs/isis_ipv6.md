# IS-IS IPv6 single-topology

## Overview

As a network operator
I want two zebra-rs instances to form an IS-IS L2 adjacency over a
Using an isolated test topology with two zebra-rs instances connected

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
          └─────────┘     └─────────┘
   lo: 2001:db8:0:ffff::1   lo: 2001:db8:0:ffff::2
              /128                  /128
```

## Config Files

- z1-1.yaml: z1 interface addresses (lo + vz1ns) + IS-IS L2 with IPv6.
- z2-1.yaml: z2 interface addresses (lo + vz2ns) + IS-IS L2 with IPv6.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup IS-IS L2 over a shared bridge and confirm the link is up | |
| IS-IS installs reciprocal IPv6 routes to peer loopbacks | |
| IS-IS adjacency survives a link bounce and routes recover | |
