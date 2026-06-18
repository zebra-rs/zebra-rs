# IS-IS per-Flex-Algorithm TI-LFA over SRv6

## Overview

Flex-Algo sibling of `tilfa_srv6`. The same proven eight-router topology
and metrics (IPv6-only, every circuit point-to-point), but each router
also runs a Flexible-Algorithm 128 (RFC 9350) on the SRv6 dataplane:

- a per-algo SRv6 locator `fcbb:bbbb:1X::/48` (usid) bound to algo 128 via
  `segment-routing srv6 flex-algo-locator`, beside the base (algo-0)
  locator `fcbb:bbbb:X::/48`;
- algo 128 has no affinity constraints, so its topology equals algo 0's —
  the per-algo TI-LFA repair mirrors the algo-0 one;
- `flex-algo 128 fast-reroute ti-lfa` enables per-algo TI-LFA, so the
  per-algo locator routes carry a repair resolved to *algo-128* End /
  End.X SIDs (SRH-inserted), keeping the repair inside algo 128.

The metrics are tuned (from `tilfa_srv6`) so a simple LFA is impossible —
protecting `s-n1` needs an SR repair tunnel through the r-plane. This
validates per-algo TI-LFA (#1469) + per-algo End.X SID origination
(#1470) end-to-end on the SRv6 dataplane. Pure-IGP (no BGP/LAN): the test
asserts the per-algo locator repair, not colour-steered service traffic.

> Like every BDD here it runs under the CI-excluded bdd suite in network
> namespaces; it was authored (reusing the proven `tilfa_srv6` topology)
> but not executed in the authoring sandbox — a real run may need
> assertion tuning.

## Config Files

s.yaml  n1.yaml  n2.yaml  n3.yaml  r1.yaml  r2.yaml  r3.yaml  d.yaml

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the per-Flex-Algo SRv6 TI-LFA topology and confirm IS-IS | |
| Per-algo SRv6 SIDs exist and algo-128 locators are reachable | |
| Algo-0 fast-reroute survives the primary link failure (s-n1) | |
| Promoted per-algo backup forwards over the algo-128 SRv6 repair | |
| Teardown topology | |
