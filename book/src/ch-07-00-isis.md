# IS-IS — Intermediate System to Intermediate System

IS-IS (ISO 10589, RFC 1195) is a link-state interior gateway protocol
operating directly over the data link layer (no IP transport). It
flood-distributes Link State PDUs (LSPs) describing each router's
local adjacencies and reachability, and each router independently
runs Dijkstra over the resulting database to compute paths.

zebra-rs implements IS-IS with the dual-level area model (L1 intra-
area, L2 inter-area, L1L2 routers participating in both), wire-format
parity with reference IOS-XR / FRR implementations, multi-topology
extensions for IPv6 (RFC 5120, MT 2), Segment Routing extensions for
MPLS and SRv6, and post-convergence Topology-Independent LFA repair
paths (TI-LFA, RFC 9490).

This section documents operational tuning surfaces. See `router isis`
under `/router/isis` in the YANG schema for the full configuration
tree.
