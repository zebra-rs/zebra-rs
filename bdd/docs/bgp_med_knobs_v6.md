# router bgp bestpath always-compare-med and med missing-as-worst (IPv6)

## Overview

As a network operator
I want to choose how MED takes part in best-path selection — compared
across neighboring ASes or not, and a missing MED read as best or worst
So I can match the MED semantics of the rest of my network, and have a
change take effect on the routes I already hold.

By default MED is compared only between paths from the same neighboring
AS (RFC 4271 §9.1.2.2 (c)) and a missing MED counts as 0, the best
value. `router bgp bestpath always-compare-med true` compares MED
between any two paths; `router bgp bestpath med missing-as-worst true`
reads a missing MED as the worst value. Changing either re-runs best-path
selection for the routes already held, so the change is visible at once.

## Test Topology

```
    ┌──────────────────────────────────────────────────────────┐
    │                   br0 192.168.57.0/24                    │
    └─────┬───────────┬───────────┬───────────┬───────────┬────┘
     ┌────┴───┐  ┌────┴───┐  ┌────┴───┐  ┌────┴───┐  ┌────┴───┐
     │   h1   │  │   h2   │  │   h3   │  │   z1   │  │   z2   │
     │AS65081 │  │AS65082 │  │AS65081 │  │ (DUT)  │  │AS65090 │
     │   .2   │  │   .3   │  │   .4   │  │AS65001 │  │   .5   │
     │        │  │        │  │        │  │   .1   │  │        │
     └────────┘  └────────┘  └────────┘  └────────┘  └────────┘
```

## Notes

h1, h2 and h3 run tests/scripts/bgp_attr_inject_send.py; their BGP
Identifiers order h1 < h2 < h3, and every path has the same AS_PATH
length. Each path carries its own community, which z2 shows:
- 2001:db8:56:1::/64 from h1 (MED 10, community 65081:1) and from h2 (MED 5,
  community 65082:2);
- 2001:db8:56:2::/64 from h1 (no MED, community 65081:11) and from h3 (MED 5,
  community 65081:13).

- 2001:db8:56:1::/64: h1 and h2 are in different ASes, so by default MED is
  skipped and h1 wins on BGP Identifier; always-compare-med hands it to
  h2 (MED 5 < 10).
- 2001:db8:56:2::/64: h1 and h3 share an AS; h1's missing MED reads as 0 and
  wins by default; missing-as-worst hands it to h3.

## Config Files

- z1.yaml: DUT — eBGP to h1, h2, h3 (passive) and to z2; no MED knobs;
  IPv6 unicast over IPv4 sessions.
- z2.yaml: z1's downstream eBGP neighbor.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and the three speakers | |
| By default MED is skipped across ASes and a missing MED is best | |
| always-compare-med compares MED across neighboring ASes, at once | |
| med missing-as-worst makes a path without MED lose, at once | |
| Deleting the knobs restores the defaults, at once | |
| Teardown topology | |
