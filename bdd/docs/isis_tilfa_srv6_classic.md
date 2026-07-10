# IS-IS TI-LFA fast-reroute over SRv6 classic (full) SIDs with BGP L3 service traffic

## Overview

As a network operator
I want eight zebra-rs instances running IS-IS Level-2 with SRv6
locators and TI-LFA (RFC 9855) to pre-compute a topology-independent
repair for the source's primary path as an SRv6 SID list (End /
End.X SIDs, SRH-inserted), so that when the primary link fails the
source still reaches the destination — including BGP-carried SRv6
service traffic between LAN segments behind the source and the
destination.
This is the classic-SID sibling of @tilfa_srv6 (same eight-router
topology, metrics and addressing). The only configuration difference
is the locator: `behavior usid` is omitted, so every router's
locator fcbb:bbbb:X::/48 allocates SIDs in the classic RFC 8986
full-SID layout instead of the RFC 9800 NEXT-C-SID (micro-SID)
format. Observable consequences this feature pins:
- `show segment-routing srv6 sid` lists the node SID as `End` and
- the End SID is the locator network address installed as a /128
- everything else is unchanged: the repair is still an SRH
The metrics are tuned so a simple LFA is impossible: s reaches d via
s-n1 (cost 2); protecting the s-n1 link requires an SR repair tunnel
through the r-plane rather than a plain loop-free alternate.

## Test Topology

```
   e1 ── s (2001:db8::1, fcbb:bbbb:1::/48)
             1 / 1 \      \ 1000
              n1    n2     n3        (n1 ::2, n2 ::3, n3 ::4)
          1 / |1 \1  \1     \1000
       d ─┘ 1 |   \    \      \
  (2001:db8::8)│    \1000\      \
    fcbb:8::/48│     r1───────── (r1-n3 1000)   (r1 ::5)
   e2 ── d 1 \ │    /  \1000
              r3   /1   \(r1-r2 1000)           (r2 ::6)
          1000\   /      \
               r2 ────────┘                     (r3 ::7)
                 \1000
                  r3 (r3-d 1)
    s-n1 1  s-n2 1  s-n3 1000   n1-r1 1  n2-r1 1  n3-r1 1000
    n1-r2 1 r1-r2 1000 r2-r3 1000  n1-d 1  r3-d 1
    s-LAN: 2001:db8:100::/64 (e1)   d-LAN: 2001:db8:200::/64 (e2)
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the classic-SID SRv6 TI-LFA topology and confirm IS-IS + BGP | |
| Classic SRv6 End/End.X SIDs exist and a TI-LFA SRv6 repair is installed | |
| BGP carries the LAN prefixes as SRv6 End.DT6 service routes | |
| Fast-reroute survives the primary link failure (s-n1) | |
| Promoted backup actually forwards over the SRv6 repair | |
| Teardown topology | |
