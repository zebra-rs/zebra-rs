# BGP neighbor-group afi-safi inheritance on an IPv6 unnumbered iBGP session

## Overview

As a network operator
I want an interface-keyed (IPv6 unnumbered) neighbor to inherit its
enabled address families from a referenced neighbor-group, so that a
fleet of unnumbered peers shares one afi-safi definition — and a
later change to the group (disable IPv4) takes effect at the next
capability negotiation (`clear bgp`), exactly like the per-neighbor
`afi-safi <name> enabled` knob.
Configuration shape under test (flattened `neighbor-group` list —
no `neighbor-groups` container level):
Test Topology (point-to-point veth, link-local only — no global addrs,
both routers in AS 65001, `remote-as internal` = iBGP):
```
```

## Config Files

- z1-base.yaml / z2-base.yaml: bare `router bgp` block (two-step
- z1-full.yaml / z2-full.yaml: RA on, `neighbor-group dynamic` with
- z1-v4off.yaml / z2-v4off.yaml: flip the group's ipv4 opinion to

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology | |
| Group-inherited IPv4+IPv6 capabilities negotiate and both families exchange routes | |
| Disabling IPv4 in the group applies on clear — IPv6-only session remains | |
| Teardown topology | |
