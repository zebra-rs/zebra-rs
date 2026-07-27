# OSPFv2 per-interface authentication gates adjacency formation

## Overview

As a network operator
I want zebra-rs to authenticate OSPFv2 packets per interface — simple
password (RFC 2328 §D.3), keyed-MD5 (§D.4), HMAC-SHA (RFC 5709) and
RFC 8177 key-chains — so that adjacencies form only between routers
sharing the key, and packets with mismatched keys are dropped.

Two routers on a point-to-point link; each scenario brings the pair
up under one authentication mode and proves the adjacency reaches
Full and the loopbacks route. The final scenario proves the negative:
same mode, different secrets, no neighbor ever appears.

## Test Topology

```
    a (10.0.0.1) -- 10.0.12.0/30 -- b (10.0.0.2)

    on router X the interface toward router Y is named "ethY".
    loopbacks: a .1  b .2  (10.0.0.X/32).
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Simple-password authentication forms a Full adjacency | |
| Keyed-MD5 authentication forms a Full adjacency | |
| HMAC-SHA-256 cryptographic authentication forms a Full adjacency | |
| RFC 8177 key-chain authentication forms a Full adjacency | |
| Mismatched MD5 secrets never form a neighbor | |
| Teardown topology | |
