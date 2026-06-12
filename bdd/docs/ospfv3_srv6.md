# OSPFv3 SRv6 locator origination (RFC 9513)

## Overview

As a network operator
I want an OSPFv3 router configured with `segment-routing srv6
locator <name>` to resolve the locator from the global registry,
install its End/uN SID, and originate the SRv6 Locator LSA
(function code 42) plus the SRv6 Capabilities TLV, so that SRv6
state floods through the area exactly like the IS-IS sibling.
Phase 2 of `docs/design/ospfv3-srv6-plan.md`: origination only —
receive-side locator routes and TI-LFA SRv6 repairs are later
phases, so reachability assertions stay out of scope here.

## Test Topology

```
   z1 ──────────────── z2
   i2  2001:db8:12::/64  i1
   lo 2001:db8::1/128    lo 2001:db8::2/128
   LOC1 fcbb:bbbb:1::/48 (usid)   LOC2 2001:db8:f:2::/64 (classic)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the topology and confirm SRv6 LSA origination | |
| The locator's End/uN SID is installed in the SID registry | |
| Each Full adjacency carves an End.X SID with a global nexthop | |
| Remote locators are reachable via the SRv6 Locator LSA | |
| Removing the locator flushes the LSA and withdraws the SID | |
| Teardown topology | |
