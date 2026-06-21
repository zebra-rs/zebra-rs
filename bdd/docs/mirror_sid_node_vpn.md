# IS-IS SRv6 Mirror SID egress NODE protection — live L3VPN service failover

## Overview

A real BGP L3VPN service survives the death of its egress PE node. The
dual-homed CE ce2 hangs off the primary egress pea (a stub off pe1) and
the protector peb (reached from pe1 over a direct bypass). pea carries
the SRv6 L3VPN service for ce2 (per-VRF End.DT46) and peb advertises a
Mirror SID (End.M) protecting pea's locator.
When pea's node is killed, two opt-in mechanisms compose to keep the
service forwarding end to end:
NHT tracks pea's End.DT46 service SID (not pea's loopback), so it
resolves the retained route *through* the locator, accumulating the
Mirror SID — pe1 then double-encaps [Mirror SID, pea-SID] to peb, whose
End.M re-resolves pea's SID in its mirror context and delivers to ce2.
Topology (loopback 2001:db8::X, SRv6 locator fcbb:bbbb:X::/48):
```
```
ce2 returns to ce1 via peb in both states (peb imports ce1), so only the
forward path changes when pea dies.

## Notes

ce2 returns to ce1 via peb in both states (peb imports ce1), so only the
forward path changes when pea dies.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build topology and confirm IS-IS + BGP VPNv6 convergence | |
| Baseline — the VPN service forwards ce1 to ce2 via pea | |
| pea node death — pic-retention keeps the route and the service survives | |
| Teardown topology | |
