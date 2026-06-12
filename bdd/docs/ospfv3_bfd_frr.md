# OSPFv3 TI-LFA kernel-side fast-reroute on BFD failure

## Overview

As a network operator
I want a BFD-detected primary failure (the link stays up, so the
kernel cannot see it) to rewire the pre-installed protection
indirection groups onto their TI-LFA repairs in one atomic kernel
operation per failed adjacency, BEFORE SPF reconvergence rewrites
the routes — phase 4 of docs/design/nexthop-protect-kernel-failover.md,
the OSPFv3 sibling of isis_tilfa_bfd.feature.
The topology is the ospfv3_tilfa SR-MPLS ring with BFD
enabled on the protected s<->n1 adjacency. BFD-down is induced by
dropping inbound UDP/3784 in namespace s: the veth link stays up and
hellos keep flowing, so the teardown is provably BFD's doing — the
failure class the kernel's autonomous link-down flush cannot cover.
The switchover is observable only in the daemon log ("rewired N
protection group(s) onto repairs" is emitted ONLY when at least one
group moved): its kernel state is superseded within milliseconds by
the post-convergence SPF routes, by design.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the topology and confirm adjacency, BFD, and repairs | |
| BFD-down with the link up triggers the kernel-side switchover | |
| Teardown topology | |
