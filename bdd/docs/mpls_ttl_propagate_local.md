# MPLS TTL propagate-local — the RFC 3443 forwarded/local split (kernel half)

## Overview

As an operator running MPLS with the RFC 3443 TTL model
I want to choose the label-TTL model for the router's OWN (locally
originated) traffic independently of forwarded/transit traffic
So that I can hide the LSP core from customer traceroutes (forwarded
`pipe`) while still seeing every P router from the PE itself (local
`uniform`) — the IOS `mpls ip propagate-ttl [forwarded | local]` split.

Forwarded traffic is imposed by the cradle eBPF data plane (governed by
`mpls ttl propagate`). Locally-originated traffic is imposed by the host
kernel's own MPLS stack (the lwtunnel encap routes zebra installs), so the
local half is the global `net.mpls.ip_ttl_propagate` sysctl. This feature
validates that config surface end to end in a running daemon: the YANG
parses, the callback drives the sysctl, and a live change / delete tracks
it. `net.mpls.ip_ttl_propagate`: 1 = uniform (propagate), 0 = pipe (hide).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| propagate-local pipe seeds the kernel MPLS TTL sysctl to 0 | |
| Flipping to uniform live restores propagation (sysctl 1) | |
| Deleting the leaf restores the uniform default (sysctl 1) | |
| Teardown topology | |
