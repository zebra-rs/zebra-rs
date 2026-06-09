# BGP TTL Security / GTSM (RFC 5082)

## Overview

As a network operator
I want to protect a directly-connected eBGP session with the
Generalized TTL Security Mechanism (GTSM) so that only a peer one hop
away — whose packets arrive with TTL 255 — can keep the session up.

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

- z1-1.yaml: AS 65001, neighbor 192.168.0.2 WITH `ttl-security`.
- z2-1.yaml: AS 65002, neighbor 192.168.0.1 WITHOUT `ttl-security`
- z2-2.yaml: AS 65002, neighbor 192.168.0.1 WITH `ttl-security`
- Asymmetric: z2 still sends at the default TTL (64). z1's minimum-TTL
- Symmetric: once z2 also pins egress to 255, z1 accepts its packets

GTSM sends BGP at TTL 255 and the kernel drops any segment that
arrives below 255 (IP_MINTTL). A Linux bridge does not decrement TTL,
so the two scenarios isolate the two halves of the mechanism:

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Asymmetric ttl-security keeps the session down | |
| Enabling ttl-security on both ends establishes the session | |
| Teardown topology | |
