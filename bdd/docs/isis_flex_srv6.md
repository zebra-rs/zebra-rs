# IS-IS Flexible Algorithm over the SRv6 dataplane

## Overview

SRv6 sibling of `isis_flexalgo`. The same five-node, two-region backbone
(se, ch, va, ln, fr) with the same affinity-constrained algorithms, but
the Flex-Algo dataplane is SRv6 (RFC 9352 §7.1) instead of SR-MPLS.

Every node advertises a distinct per-algorithm SRv6 locator, so reaching
a node "in algo N" is plain longest-prefix IPv6 to that node's algo-N
locator computed over the algo-N constrained topology — no per-prefix SID
is pushed for transit. The algorithm is encoded by *which locator you
target*.

  - Algo 128 (US-only): exclude-any [eu, transatlantic]
  - Algo 129 (EU-only): exclude-any [transatlantic, us]

ch originates the FAD for both algorithms; the others participate without
advertising a FAD.

Per-node SRv6 locators (/48): `2001:db8:<n>000::` (base / algo-0),
`2001:db8:<n>128::` (algo-128), `2001:db8:<n>129::` (algo-129), where
`<n>` is a..e for se, ch, va, ln, fr.

## Config Files

se.yaml  ch.yaml  va.yaml  ln.yaml  fr.yaml

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
