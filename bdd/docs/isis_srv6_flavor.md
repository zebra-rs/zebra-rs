# IS-IS advertises PSP-flavored SRv6 endpoint behaviors

## Overview

As a network operator
I want a locator's configured RFC 8986 §4.16 flavors folded into the
advertised endpoint-behavior codepoints, so receivers know the SRH
will be popped at this node and the data planes agree on the wire
format.
z1's uSID locator carries `flavor: [psp]`: its End SID must advertise
as `uN (PSP)` (IANA codepoint 44, End with NEXT-CSID & PSP) and its
End.X SID as `uA (PSP)` (53) — adjacency SIDs fold only the PSP bit.
z2 is flavorless and must (a) keep advertising plain `uN`/`uA` and
(b) still classify z1's flavored codepoints as NEXT-C-SID, so the
adjacency and SPF are unaffected.

## Test Topology

```
   z1 ──2001:db8:0:12::/64── z2
   LOC1 fcbb:bbbb:1::/48      LOC2 fcbb:bbbb:2::/48
   usid + flavor [psp]        usid (no flavor)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| The flavored codepoints appear in the peer's database | |
| Teardown topology | |
