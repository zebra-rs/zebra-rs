# IS-IS advertises End.T / uT for VRF-bound SRv6 locators

## Overview

As a network operator
I want a locator bound to a VRF (`vrf` leaf) to advertise its node
SID as End.T — or uT for a uSID locator — so receivers know the End
walk's egress lookup happens in the bound table (RFC 8986 §4.3).
z1's classic locator carries `vrf: vrf-one` and `flavor: [psp]`: its
End SID must advertise as `End.T (PSP)` (IANA codepoint 10). z2's
uSID locator carries `vrf: vrf-two`: its node SID advertises as `uT`
(End.T with NEXT-CSID, codepoint 85). The adjacency SIDs stay
End.X/uA, and SPF/reachability must be unaffected.

## Test Topology

```
   z1 ──2001:db8:0:12::/64── z2
   LOC1 fcbb:bbbb:1::/48      LOC2 fcbb:bbbb:2::/48
   classic + vrf-one + psp    usid + vrf-two
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| The table-scoped codepoints appear in the peer's database | |
| Teardown topology | |
