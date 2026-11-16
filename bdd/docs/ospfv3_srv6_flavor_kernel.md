# A flavored SRv6 locator keeps its SIDs in the kernel

## Overview

As a network operator
I want the End and End.X SIDs of a locator with RFC 8986 §4.16 flavors
to stay installed in the kernel when the kernel does not perform a
flavor, so that segment lists passing through those SIDs keep working.

The kernel performs PSP on End and no flavor on End.X; USP and USD it
performs nowhere. It refuses the whole route for a flavor it does not
perform. zebra-rs used to stop there, so `flavor usd` removed the End
SID from the kernel and `flavor psp` every End.X SID. It now offers
the kernel the configured flavors, then PSP alone, then none.

z2's locator carries `flavor: [psp, usd]`. The advertisement keeps
both (End with PSP & USD, codepoint 29). In the kernel the End SID
lands without USD and the End.X SIDs plain, and a two-segment list
from z1 through z2's End SID reaches z3.

## Test Topology

```
   z1 ───────────────── z2 ───────────────── z3 ─────────────── h3
      2001:db8:12::/64     2001:db8:23::/64     2001:db8:300::/64
   LOC1 fcbb:bbbb:1::/48   LOC2 fcbb:bbbb:2::/48   LOC3 fcbb:bbbb:3::/48
                           flavor [psp, usd]       End.DT6 fcbb:bbbb:3:e064::
```

## Notes

h3 is a host, 2001:db8:300::100; z3-h3 is not in OSPFv3.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| The flavored SIDs are in the kernel | |
| The show commands print the flavors | |
| A segment list passes through the flavored End SID | |
| Teardown topology | |
