# BGP eBGP multihop TTL (RFC 4271)

## Overview

As a network operator
I want to configure `ebgp-multihop` on an eBGP neighbor so that a peer
more than one hop away can be reached, and confirm the option is
accepted end-to-end and does not break a session.

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
```

## Config Files

- z1-1.yaml: AS 65001, neighbor 192.168.0.2 with `ebgp-multihop 5`.
- z2-1.yaml: AS 65002, neighbor 192.168.0.1 with `ebgp-multihop 5`.

Scope note: a genuine multi-hop test (peer behind a router, where the
default eBGP TTL of 1 would be dropped and `ebgp-multihop` is required)
needs a forwarding middle node, which the bridge-based harness cannot
build. This scenario validates the YANG/dispatch path (`ebgp-multihop:
5` is parsed and applied) and that raising the egress TTL to 5 does not
break a directly-connected session. The default-TTL-1 directly-
connected case is covered by @bgp_basic_ebgp, and the egress-TTL
resolution itself is unit-tested (`session_ttl`).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| A directly-connected eBGP session establishes with ebgp-multihop set | |
| Teardown topology | |
