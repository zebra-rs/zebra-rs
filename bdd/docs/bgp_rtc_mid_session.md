# RT Constraint membership that changes mid-session takes effect (IPv4)

## Overview

As a network operator
I want a VRF import route-target added or removed on a PE after its
session is up to change the VPN routes that PE is sent
So a new VRF gets its routes without a session reset, and a PE stops
being sent routes it no longer imports.

With RT Constraint (RFC 4684) a PE advertises the route-targets it
imports, and its neighbor sends it only the VPN routes carrying them. A
zebra-rs PE advertised that membership only at session-up, and a
neighbor that learned a new membership mid-session only recorded it,
sending none of the routes it selects; a withdrawn membership was
ignored. The twin is `bgp_rtc_mid_session_v6`.

## Test Topology

```
  ┌─────────────────────────────────────┐
  │         br0 192.168.67.0/24         │
  └───────┬─────────────────────┬───────┘
     ┌────┴────┐           ┌────┴────┐
     │   z1    │── iBGP ───│   z2    │
     │ AS65000 │ vpnv4+rtc │ AS65000 │
     │  .1     │           │  .2     │
     └─────────┘           └─────────┘
```

## Notes

z1 exports 10.29.1.0/24 (VRF red, RT 65000:100) and 10.29.2.0/24 (VRF green,
RT 65000:200). z2's VRF blue imports 65000:100, so z1 sends z2 only
10.29.1.0/24. z2 then imports 65000:200 too, and later stops.

## Config Files

- z1.yaml: the two exporting VRFs; iBGP vpnv4 + RT Constraint to z2.
- z2.yaml: VRF blue importing 65000:100; iBGP vpnv4 + RT Constraint to z1.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup; z2 is sent only the route its membership selects | |
| An import route-target added mid-session brings its routes | |
| The import route-target removed mid-session withdraws its routes | |
| Teardown topology | |
