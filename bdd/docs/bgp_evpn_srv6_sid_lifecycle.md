# EVPN-over-SRv6 L2 service SIDs track the locator's lifecycle

## Overview

As a network operator whose SRv6 locator is configured, moved or removed
independently of the EVPN service
I want the per-VNI End.DT2U / End.DT2M SIDs to be (re)attached to the
already-originated Type-2 / Type-3 routes whenever the locator's usable
prefix changes, so a locator that resolves late — or moves, or goes away
— never leaves the peer holding a route pointing at a SID that was never
carved or no longer exists.
This is the reconcile documented in `Bgp::process_sr_rx`: on a material
prefix change it re-seeds the SID pool and re-originates every MAC route
and IMET so the SIDs follow. Route origination and locator resolution
are independent events, so all three orderings are reachable in practice
and none of them had coverage.
z1 deliberately starts with `advertise-all-vni` + `encapsulation srv6`
but NO locator object — its BGP instance references LOC1 before LOC1
exists. z2's locator resolves normally throughout, so it is a stable
observer: its own SIDs render as "Local SID" and z1's as "Remote SID",
which is what lets a missing-SID assertion on z2 be specifically about
z1's routes.
```
```

## Config Files

- z1-nolocator.yaml — references LOC1, which does not exist yet.
- z2.yaml — LOC2 resolved from the start.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup with z1's locator absent | |
| Routes originated before the locator resolves go out SID-less | |
| Creating the locator re-originates the routes with their SIDs | |
| Moving the locator prefix re-carves the SIDs under the new one | |
| Withdrawing the locator strips the SIDs but keeps the routes | |
| Teardown topology | |
