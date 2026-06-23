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

## Identity: NET and TE Router ID

IS-IS does not use an IPv4 router-id for its own identity — the
configured NET (Network Entity Title) supplies the system-id that
names the router in the link-state database:

```
set router isis net 49.0000.0000.0000.0001.00
```

The IPv4-shaped identity IS-IS *does* advertise is the stable
Traffic Engineering Router ID, carried in TLV 134 and in the Router
Capability TLV (both emitted when segment routing is enabled):

```
set router isis te-router-id 1.1.1.1
```

When `te-router-id` is not configured, the RIB-distributed router-id
(the system-wide selection, or the configured `system router-id`)
is advertised instead. Setting or deleting `te-router-id`
re-originates the self LSP immediately, so the change propagates
without waiting for the refresh timer. A per-VRF instance accepts
`set router isis vrf <name> te-router-id`, which is stored and goes
on the wire once per-VRF segment routing is available. See
[Selection of the Router-ID](ch-00-01-router-id.md) for the
system-wide selection and precedence model.
