# BGP zero adv-interval delivers routes across IPv6 families

## Overview

As a network operator
I want `router bgp timer adv-interval ibgp 0` to disable the MRAI
debounce without stalling advertisement
Using a two-namespace iBGP topology over IPv6 transport that carries
IPv6 unicast and VPNv6, both with adv-interval 0.
IPv6 counterpart of @bgp_adv_interval_zero. Regression guard for the
adv-interval-0 fast-flush path (a 0-second MRAI arms a ~1 ms next-tick
debounce timer instead of the old 1 s-clamped one): each family's
routes must still converge at the peer.

## Test Topology

```
  ┌─────────────┐                ┌─────────────┐
  │     z1      │   iBGP AS65001 │     z2      │
  │ 2001:db8::1 │ ◀────────────▶ │ 2001:db8::2 │
  │ vrf-blue    │   ipv6/vpnv6   │ vrf-blue    │
  │  RD 65001:  │  adv-interval  │  RD 65001:  │
  │   100       │    ibgp 0      │   200       │
  │  RT 65001:100 imp/exp        │  RT 65001:100 imp/exp
  └─────────────┘                └─────────────┘
```

## Config Files

- z1-1.yaml: AS 65001, adv-interval ibgp 0, neighbor 2001:db8::2 with
- z2-1.yaml: AS 65001, adv-interval ibgp 0, same address families,

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish the multiprotocol session | |
| IPv6 unicast route converges with adv-interval 0 | |
| VPNv6 route converges with adv-interval 0 | |
| Teardown topology | |
