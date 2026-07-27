# MLD membership tracking on a PIMv6 router

## Overview

As a network operator
I want a zebra-rs router running MLD on an IPv6 interface to act as
the querier and learn group memberships from MLDv2 reports, so the
MLD codec (RFC 3810 over ICMPv6) driving the shared Gm<Ipv6> engine
is exercised host-to-router.

A host joins an IPv6 multicast group; its kernel emits an MLDv2
report to ff02::16, which the router's querier (joined to ff02::16)
receives and records as membership.

## Test Topology

```
    r1 (2001:db8:1::1/64, MLD querier) --- veth --- h1 (2001:db8:1::9/64)
       eth1                                            eth2
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| An MLDv2 report creates group membership on the querier | |
| Teardown topology | |
