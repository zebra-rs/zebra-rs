# Routes appearing after establishment reach an IPv6-unnumbered peer

## Overview

As a network operator running BGP over IPv6-only point-to-point links
I want routes that show up while an interface-keyed (unnumbered)
session is already Established to be advertised to that peer, so
convergence on unnumbered fabrics does not depend on session resets.
Regression guard: every incremental advertise fan-out collected
peers by remote address (`PeerMap::iter()` + `get_mut(&addr)`),
which silently skips `PeerKey::Interface` peers — an unnumbered
peer's remote link-local is never written into the address map. An
interface-keyed session received the initial `route_sync` dump at
establishment and then nothing: no reach, no withdraws, in any
family. The fan-outs now collect peer idents over `iter_all()`,
which is key-agnostic.
Topology: the bgp_unnumbered_neighbor P2P link (link-local only,
RA-discovered interface-neighbor on both ends, IPv4 carried via
RFC 8950 ENHE). The route under test is a `network` statement
applied only AFTER the session is verified Established, so it can
only reach the peer through the incremental path (initial-config
networks ride the route_sync dump, which always worked).
adv-interval is pinned to 1s in the configs — the incremental
reach flushes through the update-group debounce.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| A network added after Established reaches the unnumbered peer | |
| A network removed after Established is withdrawn from the unnumbered peer | |
| Teardown topology | |
