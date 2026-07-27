# OSPFv3 native authentication config drives the RFC 7166 trailer

## Overview

As a network operator
I want `router ospfv3 area <id> interface <n> authentication
message-digest` with `crypto-key` / `key-chain` to configure the
RFC 7166 Authentication Trailer natively — no `router ospf` block
required in an IPv6-only deployment — so adjacencies form only
between routers sharing the key.

Two routers on a point-to-point link; each scenario brings the
pair up under one keying mode. The final scenario proves the
negative: same SA-ID, different secrets, no neighbor ever forms.

## Test Topology

```
    a (10.0.0.1) -- 2001:db8:12::/64 -- b (10.0.0.2)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| HMAC-SHA-256 trailer via native crypto-key forms a Full adjacency | |
| RFC 8177 key-chain supplies the trailer key | |
| Mismatched trailer secrets never form a neighbor | |
| Teardown topology | |
