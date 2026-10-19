# EVPN route reflector keeps a Type-5 route's ESI and Gateway IP

## Overview

As a network operator
I want a zebra-rs route reflector to pass a Type-5 (IP Prefix) route on
with the ESI and Gateway IP it arrived with, because those two NLRI
fields are the route's overlay index (RFC 9136 §3.2) — the ESI is what
IP aliasing resolves through — and a reflector that zeroes them turns
the route into an interface-less one behind the receivers' backs.

Before the fix the reflector kept only the label of a received Type-5:
the ESI and Gateway IP were dropped at receive, `show bgp evpn` did not
list them, and the reflected route went out with both zeroed. zebra-rs
originates interface-less Type-5 routes only, so a scripted speaker
plays the sender.

## Test Topology

```
  ┌─────────────────────────────────────────────────────────┐
  │                          br0                            │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │          │   z1    │          │   z2    │
     │ scripted│          │  (DUT)  │          │ zebra-rs│
     │ Type-5  │─iBGP────▶│  route  │─iBGP────▶│ client  │
     │ AS65000 │          │reflector│          │ AS65000 │
     │ .31.2/24│          │ .31.1/24│          │ .31.3/24│
     └─────────┘          └─────────┘          └─────────┘
```

## Notes

h1 runs tests/scripts/bgp_evpn_type5_send.py and announces three
Type-5 routes under RD 192.168.31.2:100:
- 10.20.0.0/24, ESI 00:11:22:33:44:55:66:77:88:99, Gateway IP 10.20.0.1
- 2001:db8:20::/64, the same ESI, Gateway IP 2001:db8:20::1
- 10.30.0.0/24 with neither, the interface-less control

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish sessions | |
| The reflector lists each Type-5 path's ESI and Gateway IP | |
| The reflected Type-5 routes keep their ESI and Gateway IP | |
| A Type-5 route without an overlay index is reflected without one | |
| Teardown topology | |
