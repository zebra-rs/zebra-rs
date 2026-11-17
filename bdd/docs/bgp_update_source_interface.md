# BGP update-source by interface name

## Overview

As a network operator
I want `update-source <interface>` to source a neighbor's session from
that interface's address, whatever the address is and whenever it
comes, so that the configuration names the loopback and never its
address (SONiC: `neighbor BGPMON update-source Loopback4096`).

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65001 │
           │ 10.0.0. │     │ 10.0.0. │
           │  1/24   │     │  2/24   │
           │ 2001:   │     │ 2001:   │
           │ db8::1  │     │ db8::2  │
           │ lo: set │     │ lo .255 │
           │ by the  │     │  .0.2   │
           │ scenario│     │ :255::2 │
           └─────────┘     └─────────┘
```

## Notes

z1 dials z2's loopback (iBGP, reached by a static route) with
`update-source lo`. z2 is the observer: it never dials, and it has a
passive neighbor for each address z1 could dial from — z1's loopback
addresses, and z1's link addresses 10.0.0.1 / 2001:db8::1, which are
what the kernel picks when z1 binds no source. So which of z2's
sessions comes up says which address z1 sourced the session from:

- with a loopback address: z1 bound what `lo` gives;
- with a link address: z1 dialed without the source it was asked for.

## Config Files

- z2.yaml: the observer.
- z1-neighbor.yaml: `update-source lo` on the neighbor; `lo` without
  an address.
- z1-group.yaml: `update-source lo` on a neighbor-group with an IPv4
  and an IPv6 member; `lo` with an address of each family.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| A neighbor is not dialed while the interface has no address | |
| It is dialed from the interface's address when one comes | |
| The next connect follows the interface to its new address | |
| One neighbor-group statement sources IPv4 and IPv6 members | |
| Teardown topology | |
