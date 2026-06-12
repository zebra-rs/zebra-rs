# BGP IPv6 unnumbered neighbor discovered via Router Advertisements

## Overview

As a network operator running BGP over IPv6-only point-to-point links
I want a peer keyed by its outbound interface (no configured remote
address) to be discovered from the neighbour's Router Advertisement,
establish a session over the link-local, carry IPv4 routes via
RFC 8950 Extended Next Hop Encoding, and forward IPv4 traffic
through the kernel FIB over the IPv6 link-local next-hop (RFC 5549
style `via inet6 fe80::.. dev i1`).
This exercises the full unnumbered path end-to-end through the
YAML/YANG/CLI stack — ND RA send + receive, NeighborDiscovered →
interface-keyed Peer materialization, the active-connect over
fe80::%ifindex AND the passive accept that binds an inbound
link-local connection back to its interface-keyed peer (both ends
connect actively and accept passively, so a collision must resolve
into a single Established session), ENHE-carried IPv4 routes, and
the v4-over-v6 dataplane: each router owns an IPv4 LAN prefix on a
dummy interface, learns the other's via ENHE, installs it in the
kernel with the v6 link-local gateway, and pings across.
Test Topology (P2P veth, link-local only — no v4/global-v6 addrs on
i1; the LAN prefixes live on dummy interfaces):
```
```

## Config Files

- z1-base.yaml / z2-base.yaml: a bare `router bgp` block — spawns ND
- z1-full.yaml / z2-full.yaml: enable `send-advertisements` on i1,

Note: the interface-keyed peer's remote address is a kernel-assigned
link-local that the scenario can't name, so the session is asserted
with the address-agnostic "BGP session in namespace … should
eventually be …" step (it reads `show bgp neighbors`, which lists
interface-keyed peers), and the FIB assertion pins the substring

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| RA discovery establishes the unnumbered session and exchanges IPv4 routes | |
| IPv4 LAN prefixes forward over the IPv6 link-local next-hop | |
| The unnumbered peer is listed in summaries and addressable by interface name | |
| Removing the interface-neighbor tears the session down | |
| Teardown topology | |
