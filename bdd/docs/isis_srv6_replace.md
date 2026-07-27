# IS-IS advertises REPLACE-C-SID SRv6 endpoint behaviors

## Overview

As a network operator
I want a locator's RFC 9800 REPLACE-C-SID format reflected in the
advertised endpoint-behavior codepoints and SID structure, so SR
source nodes can compress segment lists with 32-bit C-SIDs and the
data planes agree on the wire format.

z1's locator carries `behavior: replace` and `flavor: [psp, usd]`:
its End SID must advertise as `End (REP, PSP, USD)` (IANA codepoint
129, End with REPLACE-CSID, PSP & USD) and its End.X SID as
`End.X (REP, PSP)` (106) — adjacency SIDs fold only the PSP bit.
The advertised structure is LB 48 / LN 16 / Fun 16 / Arg 48 — the
non-zero argument length is how receivers infer 32-bit compression
(RFC 9800 §6.4). z2 is a plain uSID locator and must keep
advertising `uN`/`uA`, and the adjacency and SPF must be unaffected
by the REPLACE codepoints.

## Test Topology

```
   z1 ──2001:db8:0:12::/64── z2
   LOC1 fcbb:bbbb:1:1::/64    LOC2 fcbb:bbbb:2::/48
   replace + psp,usd          usid (no flavor)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| The REPLACE-C-SID codepoints appear in the peer's database | |
| Teardown topology | |
