# BGP MUP capability (re)negotiates when enabled on a live session

## Overview

An AFI/SAFI is a BGP Multiprotocol *capability*, advertised once in the
OPEN — the negotiated set is fixed for the life of the session. So
enabling `afi-safi mup` (RFC 9833, which turns on BOTH IPv4-MUP
and IPv6-MUP) on an already-Established neighbor has no effect until the
session renegotiates. zebra-rs therefore bounces the session on the
change — the same teardown `clear bgp ... hard` uses — so the new MUP
capability is advertised and received without an operator clear.
This regressed silently before: the config was recorded but the live
session was never bounced, so `show bgp neighbor` kept showing the old
capability set (no MUP).

## Test Topology

```
   z1 (AS65001, 192.168.0.1) ── br0 ── z2 (AS65001, 192.168.0.2)
   both start IPv4-unicast only; mup is enabled at runtime.
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Enabling mup at runtime renegotiates the MUP capability | |
| Teardown topology | |
