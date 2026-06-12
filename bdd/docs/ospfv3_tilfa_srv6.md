# OSPFv3 TI-LFA fast-reroute over SRv6

## Overview

As a network operator
I want eight zebra-rs instances running OSPFv3 with SRv6 locators
(RFC 9513) and TI-LFA (RFC 9490) to pre-compute a topology-
independent repair for the source's primary path as an SRv6 SID
list — End/uN of the P-node plus uA hops, NEXT-C-SID-compressed and
SRH-inserted — so that when the primary link fails the source still
reaches the destination.
Phases 5+6 of `docs/design/ospfv3-srv6-plan.md`: the OSPFv3 sibling
of `isis_tilfa_srv6.feature` (same eight-router RFC 9855 §5
topology and metrics as `ospfv3_tilfa.feature`, with the SR-MPLS
machinery replaced by uSID locators fcbb:bbbb:X::/48). Repairs ride
the carriers validated for IS-IS in #1364, the End.X kernel entries
carry neighbor-global nexthops per #1361, and the promoted-backup
scenario proves the repair dataplane genuinely forwards — the
coverage rule every TI-LFA feature carries since #1361.

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
| Build the TI-LFA topology and confirm adjacencies + SRv6 | |
| SRv6 SIDs exist and a TI-LFA SRv6 repair is installed | |
| Fast-reroute survives the primary link failure (s-n1) | |
| Promoted backup actually forwards over the SRv6 repair | |
| Teardown topology | |
