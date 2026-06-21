# IS-IS Flexible Algorithm over the SRv6 dataplane

## Overview

SRv6 sibling of @isis_flexalgo. Same five-node, two-region backbone and
the same affinity-constrained algorithms, but the Flex-Algo dataplane is
SRv6 (RFC 9352 §7.1): every node advertises a distinct per-algorithm
SRv6 locator, so reaching a node "in algo N" is plain longest-prefix
IPv6 to that node's algo-N locator computed over the algo-N constrained
topology — no per-prefix SID is pushed for transit.
Topology (all links point-to-point; default metric 10):
Per-node SRv6 locators (/48):
The FAD for both algorithms is originated by ch; every other router
participates without advertising a FAD.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the SRv6 Flex-Algo topology and confirm IS-IS adjacencies | |
| Local per-algo SRv6 locators are visible on the originator | |
| Per-algo SRv6 locators flood to non-originating routers | |
| Algo 128 (US-only) SRv6 routes confine to the US sub-topology | |
| Algo 129 (EU-only) SRv6 routes confine to the EU sub-topology | |
| Per-algo SRv6 locator routes install into the IPv6 FIB | |
| Teardown SRv6 Flex-Algo topology | |
