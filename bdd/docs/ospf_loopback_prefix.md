# OSPF never advertises the loopback address

## Overview

As a network operator
I want OSPF to advertise the addresses I configure on `lo` but never
the loopback address the kernel puts there itself — 127.0.0.1/8 and
::1/128 must not leave the node (RFC 1122 §3.2.1.3, RFC 4291 §2.5.3).

OSPFv3 used to advertise ::1/128 in every router's
Intra-Area-Prefix-LSA and lo's Link-LSA whenever lo was enabled, and
installed it as a route of its own. OSPFv2 already left out
127.0.0.0/8; the feature checks both versions.

## Test Topology

```
    r1 (10.0.0.1, 2001:db8::1) ---- r2 (10.0.0.2, 2001:db8::2)
        192.168.12.0/24 and 2001:db8:12::/64, point-to-point
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the topology | |
| OSPFv3 advertises the configured loopback but not ::1 | |
| OSPFv2 advertises the configured loopback but not 127.0.0.0/8 | |
| Teardown topology | |
