# BGP per-VRF VPNv6 origination (network) + receive on a remote PE

## Overview

Regression guard for VPNv6 VRF-`network` origination — the v6 sibling of
`materialize_self_originated_networks` in vrf/spawn.rs that was missing —
and the VPNv6 advertise path (V6Batch). z1 originates two v6 networks
inside vrf-blue at VRF spawn; they are exported as VPNv6 NLRIs and
received by z2. Killing z1 withdraws them from z2.
Topology: z1 (RD 65001:100) <-VPNv6 iBGP-> z2 (RD 65001:200), both AS
65001, vrf-blue importing/exporting RT 65001:100, over a native IPv6 link
(so VPNv6 next-hop-self is a valid v6 address).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology (z1 originates its vrf-blue v6 networks at spawn) | |
| z1 originates the vrf-blue v6 networks; z2 receives them as VPNv6 | |
| z1 dies; z2 withdraws the VPNv6 routes it learned from it | |
| Teardown topology | |
