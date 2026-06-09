# BGP show command tree (show bgp ...)

## Overview

As a network operator
I want the new `show bgp [ipv4|ipv6] [<addr>|<prefix> [longer-prefix]]`
command tree to render the BGP RIB, including the IPv4 shortcut where
an address or prefix is typed straight after `show bgp` (no AFI keyword).

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬────────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
```

## Notes

z1 originates a covering prefix (10.0.0.0/24), a more-specific
(10.0.0.128/25), and a host route (10.0.0.1/32) so the longest-match
and longer-prefix views have a real prefix hierarchy to display. z2 is
the receiver where the `show bgp ...` output is checked.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish BGP session | |
| Routes propagate to z2 | |
| "show bgp" defaults to the IPv4 unicast table | |
| "show bgp ipv4" renders the same IPv4 unicast table | |
| "show bgp A.B.C.D" shortcut shows the longest match | |
| "show bgp A.B.C.D/M" shortcut shows the exact prefix | |
| "longer-prefix" shows the prefix and every more-specific entry | |
| "show bgp ipv6" dispatches to the IPv6 unicast table | |
| Teardown topology | |
