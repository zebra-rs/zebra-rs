# IS-IS SRv6 Mirror SID egress link protection — steady-state baseline

## Overview

A dual-homed CE (ce2) hangs off both the primary egress pea and the
protector peb. pea carries the BGP L3VPN service for ce2 over SRv6
(per-VRF End.DT46), and peb advertises a Mirror SID (End.M) protecting
pea's locator with via-vrf vrf-cust, so on a pea PE-CE link failure pea
can redirect its own service SID to peb's Mirror SID. This feature
validates the steady state that the failover test builds on: the VPN
forwards via pea, the Mirror SID is advertised and the End.M localsid +
mirror-context route install on peb, and pea's End.DT46 service SID is
in place. The live link-failure redirect is exercised separately.
Topology (loopback 2001:db8::X, SRv6 locator fcbb:bbbb:X::/48):
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
| Build topology and confirm IS-IS + BGP VPNv6 convergence | |
| The VPN service forwards ce1 to ce2 via pea (primary egress) | |
| peb advertises the Mirror SID and installs End.M + mirror-context | |
| pea installs its per-VRF End.DT46 service SID | |
| PE-CE link failure redirects via the Mirror SID | |
| Teardown topology | |
