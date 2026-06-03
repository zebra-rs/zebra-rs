# IS-IS Hello authentication via an RFC 8177 key-chain

## Overview

As a network operator
I want to authenticate IS-IS Hello (IIH) PDUs on a point-to-point link
by referencing a named key-chain (RFC 8177) instead of an inline
password, and confirm that two zebra-rs routers sharing the same chain
form a Level-1 adjacency and exchange dual-stack routes.
When an interface's `hello-authentication` carries a `key-chain` leaf
(and no inline `password`), the chain's active key is self-describing:
it supplies the algorithm (from `crypto-algorithm`), the RFC 5310 Key
ID, and the key material at both sign and verify time, so no `auth-type`
leaf is needed. Both ends must define the same chain name with an
identical key (key-id, crypto-algorithm, key-string) or the IIHs fail
to verify and the adjacency never forms — so a formed adjacency is
itself proof that keychain-based Hello auth round-trips correctly.

## Test Topology

```
    z1 --10-- z2     point-to-point veth (10.0.1.0/30, 2001:db8:1::/64)

    loopbacks: z1 -> 10.0.0.1/32  2001:db8:0:ffff::1/128
               z2 -> 10.0.0.2/32  2001:db8:0:ffff::2/128
```

## Notes

Both routers are is-type level-1 in area 49.0001. On z1 the interface
toward z2 is "i2"; on z2 the interface toward z1 is "i1". Each carries
`hello-authentication { key-chain ISIS-HELLO }`, where ISIS-HELLO has a
single hmac-sha-256 key (key-id 1, key-string "zebra-isis-hello-secret").

## Config Files

- z1.yaml: z1 with the ISIS-HELLO chain (hmac-sha-256, key-id 1, key-string "zebra-isis-hello-secret").
- z2.yaml: z2 with the same chain -- matches z1, so the adjacency forms.
- z2-badkey.yaml: z2 with the chain re-keyed to a value z1 does not share (same name/key-id/algorithm), used to prove a key mismatch tears the adjacency down.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Keychain-authenticated IIH brings up the L1 adjacency | |
| A mismatched chain key tears the adjacency down | |
| Teardown topology | |
