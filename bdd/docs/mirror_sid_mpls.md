# IS-IS SR-MPLS Mirror SID egress link protection — steady-state baseline

## Overview

A dual-homed CE (ce2) hangs off both the primary egress pea and the
protector peb. pea carries the BGP L3VPN service for ce2 over SR-MPLS
(IS-IS Prefix-SID transport + per-VRF VPN label), and peb advertises a
Mirror Context binding (SID/Label Binding TLV 149, M-flag, RFC 8679) for
pea's loopback with via-vrf vrf-cust, installing a context-label ILM
that decaps into the VRF. On a pea PE-CE link failure pea can redirect
its VPN traffic to peb's context label. This feature validates the
steady state the failover builds on: VPNv4 forwards via pea over the
SR-MPLS transport, the context binding is advertised and its ILM
installs on peb, and pea's per-VRF VPN-label ILM is in place. The live
link-failure redirect is exercised separately.
Topology (loopback 1.1.1.X/32, Prefix-SID index X -> label 1600X):
```
```
ce2 returns to ce1 via peb in both states (peb imports ce1), so the
forward path is the only thing that changes on failover. peb does not
originate ce2 into BGP — pe1 always forwards ce2-bound traffic via pea.

## Notes

ce2 returns to ce1 via peb in both states (peb imports ce1), so the
forward path is the only thing that changes on failover. peb does not
originate ce2 into BGP — pe1 always forwards ce2-bound traffic via pea.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and confirm IS-IS SR-MPLS + BGP VPNv4 | |
| The VPN service forwards ce1 to ce2 via pea (primary egress) | |
| peb advertises the Mirror Context binding and installs its ILM | |
| pea installs its per-VRF VPN-label ILM | |
| PE-CE link failure redirects via the Mirror Context label | |
| Teardown topology | |
