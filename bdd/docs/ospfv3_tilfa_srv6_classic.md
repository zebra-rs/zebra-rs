# OSPFv3 TI-LFA fast-reroute over SRv6 classic (full) SIDs

## Overview

As a network operator
I want eight zebra-rs instances running OSPFv3 with classic
(RFC 8986 full-SID) SRv6 locators and TI-LFA (RFC 9490) to
pre-compute a topology-independent repair as an SRv6 SID list, so
that when the primary link fails the source still reaches the
destination.
This is the classic-SID sibling of `ospfv3_tilfa_srv6.feature`
(same RFC 9855 §5 topology and costs). The only configuration
difference is the locator: `behavior usid` is omitted, so SIDs use
the classic RFC 8986 full-SID layout. Observable consequences this
feature pins:
- `show segment-routing srv6 sid` lists `End` / `End.X` — never the
- the repair SID list does NOT compress: each segment is a full
- everything else is unchanged: H.Insert encap, neighbor-global

## Test Topology

```
                 s (2001:db8::1)
             1 / 1 \      \ 1000
              n1    n2     n3
          1 / |1 \1  \1     \1000
       d ─┘ 1 |   \    \      \
 (2001:db8::8)│    \1000\      \
          1 \ │     r1───────── (r1-n3 1000)
             r3    /  \1000
          1000\   /1   \(r1-r2 1000)
               r2 ──────┘
                 \1000
                  r3 (r3-d 1)
    s-n1 1  s-n2 1  s-n3 1000   n1-r1 1  n2-r1 1  n3-r1 1000
    n1-r2 1 r1-r2 1000 r2-r3 1000  n1-d 1  r3-d 1
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the classic-SID TI-LFA topology and confirm adjacencies | |
| Classic End/End.X SIDs exist and the repair is uncompressed | |
| Fast-reroute survives the primary link failure (s-n1) | |
| Promoted backup actually forwards over the classic SRv6 repair | |
| Teardown topology | |
