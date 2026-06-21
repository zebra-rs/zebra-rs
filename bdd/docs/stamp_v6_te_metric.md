# STAMP link-delay measurement over an IPv6-only IS-IS link

## Overview

As a network operator running delay-based traffic engineering on an
IPv6 fabric, I want each P2P link's delay measured actively (STAMP,
RFC 8762) and advertised by IS-IS (RFC 8570 link-delay sub-TLVs) even
when the link carries no IPv4 — so dual-stack and v6-only links are
measured the same way.
Two zebra-rs instances share one IPv6-only P2P link (global addresses
for routing, link-locals for the adjacency — no IPv4 anywhere on the
measured interface). Both run IS-IS with `te-metric measurement`
enabled (probe interval 100 ms, damping period 2 s). Because no shared
IPv4 pair exists, the one STAMP session per link falls back to the
IPv6 link-local pair (the same v4-preferred / v6-LL-fallback rule BFD
uses), scoped by the link's ifindex. After the first damping period
the measured values appear as "Min/Max Unidirectional Link Delay" in
both LSDBs.
OSPF is intentionally absent: OSPFv2 is IPv4-only on the wire and
OSPFv3 has no TE-metric origination, so there is nowhere on the OSPF
side to publish an IPv6 delay (see docs/design/stamp-ipv6-plan.md §1).
Topology:

## Config Files


## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the IPv6-only measured topology | |
| A v6 link-local STAMP session forms and measures the link | |
| IS-IS advertises the measured IPv6-link delay | |
| Teardown topology | |
