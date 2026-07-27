# EVPN Type-2 / Type-3 over SRv6 — End.DT2U and End.DT2M signalling

## Overview

As a network operator running EVPN bridging over an SRv6 underlay
I want `afi-safi evpn encapsulation srv6` to carve a per-VNI End.DT2U
SID onto every Type-2 (MAC/IP) route and an End.DT2M SID onto every
Type-3 (IMET) route (RFC 9252 SRv6 L2 Service TLVs), and the receiving
PE to bind the remote End.DT2U as the MAC's overlay destination, so
that EVPN bridging signals over SRv6 with no VXLAN VTEP anywhere.

This is the `encapsulation srv6` counterpart of the VXLAN Type-2/Type-3
path. @bgp_evpn_srv6_p2mp already covers the End.DT2M half via the
SR-P2MP BUM tree; the unicast End.DT2U half — the `encapsulation srv6`
leaf itself — had no coverage at all before this feature.

Control-plane scope: the L2 forwarding plane for End.DT2U / End.DT2M is
the cradle eBPF tee (the kernel has no seg6local action for either), so
no `system ebpf` here and no frames are sent. What is proven is the SID
carve, the advertisement, the receive/import bind, the encapsulation
toggle, and the withdraw — everything up to the datapath handoff.

```
```

## Config Files

- z1.yaml, z2.yaml — `advertise-all-vni` + `encapsulation srv6`, a

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and the EVPN session over SRv6 | |
| Each PE's Type-3 IMET carries a per-VNI End.DT2M SID | |
| A local MAC originates a Type-2 carrying a per-VNI End.DT2U SID | |
| The importing PE binds the remote End.DT2U SID to the MAC | |
| Toggling the encapsulation re-originates the routes in place | |
| Withdrawing the local MAC withdraws the Type-2 and its MAC entry | |
| Teardown topology | |
