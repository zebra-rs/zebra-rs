# IS-IS per-Flex-Algorithm TI-LFA over SRv6

## Overview

Flex-Algo sibling of @tilfa_srv6. Same proven eight-router topology and
metrics (IPv6-only, every circuit point-to-point), but each router also
runs a Flexible-Algorithm 128 (RFC 9350) on the SRv6 dataplane:
- each router owns a per-algo SRv6 locator fcbb:bbbb:1X::/48 (behavior
- algo 128 has no affinity constraints, so its topology equals algo 0's
- `flex-algo 128 fast-reroute ti-lfa` enables per-algo TI-LFA, so the
The metrics are tuned (from @tilfa_srv6) so a simple LFA is impossible:
s reaches d via s-n1 (cost 2); protecting s-n1 needs an SR repair tunnel
through the r-plane. This validates per-algo TI-LFA + per-algo End.X SID
origination end-to-end on the SRv6 dataplane.
NOTE: like every BDD here this runs under the (CI-excluded) bdd suite in
network namespaces; it has not been executed in the authoring sandbox.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the per-Flex-Algo SRv6 TI-LFA topology and confirm IS-IS | |
| Per-algo SRv6 SIDs exist and algo-128 locators are reachable | |
| Algo-0 fast-reroute survives the primary link failure (s-n1) | |
| Promoted per-algo backup forwards over the algo-128 SRv6 repair | |
| Teardown topology | |
