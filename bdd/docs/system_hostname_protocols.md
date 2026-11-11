# IS-IS and BGP advertise the system hostname

## Overview

As a network operator
I want `set system hostname <name>` to be the name my router goes by in
the protocols that carry one, the IS-IS dynamic hostname (TLV 137) and
the BGP FQDN capability, when I have not given them a hostname of their
own, so that one line names the router everywhere. They used to
advertise the operating system's host name instead, whatever the
configuration said.

The order is: the protocol's own hostname (`router isis hostname`,
`router bgp global hostname`), then `system hostname`, then the
operating system's name. A change reaches IS-IS neighbors at once: the
LSP is regenerated, not left until its refresh 15 minutes later. A BGP
session keeps the name its OPEN carried, as with BGP's own hostname.

## Test Topology

```
   z1 ───────────── z2
   i2  10.0.12.0/30  i1
   lo 10.0.0.1/32   lo 10.0.0.2/32
```

## Notes

Both are level-2-only IS-IS routers on a point-to-point link, with an
iBGP session over it. z1 is `bdd-sys-one`, z2 is `bdd-sys-two`.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build two routers that have a system hostname and no protocol hostname | |
| A neighbor learns the system hostname from the IS-IS LSP | |
| A neighbor learns the system hostname from the BGP OPEN | |
| A changed system hostname reaches the IS-IS neighbor at once | |
| A BGP session keeps the name of its OPEN and the next OPEN has the new one | |
| The IS-IS hostname wins over the system hostname | |
| Without an IS-IS hostname the system hostname is advertised again | |
| Without a system hostname the neighbor stops seeing it | |
| Teardown topology | |
