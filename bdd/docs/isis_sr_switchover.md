# Live switchover IS-IS SR-MPLS -> SRv6 (classic) -> SRv6 uSID -> SR-MPLS via vtyctl apply

## Overview

As a network operator
I want to migrate a running IS-IS Segment Routing network between
dataplanes by applying each node's ENTIRE configuration with
`vtyctl apply -f` (the BDD `I apply config` step — a declarative
whole-config replace: everything the new file omits is deleted), so
an SR-MPLS domain can be moved to SRv6 classic SIDs, compressed to
NEXT-C-SID micro-SIDs, and rolled back to SR-MPLS, with each
transition tearing down the previous dataplane completely and
bringing up the next one end to end.

The per-node configurations are the playset trios (playset/
isis-srmpls, isis-srv6-classic, isis-srv6-usid) on the RFC 9855
topology: 8 core routers in IS-IS level-2-only. The three phases
observably differ on node s:
- SR-MPLS: v4 addressing; remote loopbacks carry Prefix-SID labels
- SRv6 classic: v6 addressing; locators fcbb:bbbb:X::/48 are plain
- SRv6 uSID: identical except `behavior: usid` on every locator —

e1 (behind s) and e2 (behind d) are plain dual-stack host
namespaces (no routing daemon) provisioned once with both edge
addressings and default routes; whichever edge family the routers
currently serve decides which of their pings forwards, so
edge-to-edge reachability doubles as the phase's end-to-end proof
and the retired family's ping must go dark.

Test Topology (playset/isis-srmpls; metric shown where != 1;
loopbacks 10.0.0.X / 2001:db8::X, Prefix-SID index X00, locators
fcbb:bbbb:X::/48):
```
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the topology, dual-stack edge hosts, and the SR-MPLS baseline | |
| SR-MPLS phase forwards labeled traffic end to end | |
| Switch over to SRv6 classic — whole-config replace swaps the dataplane | |
| The BGP SRv6 service layer carries the edge LANs after the switchover | |
| Switch over to SRv6 uSID — locators recompress, the service layer never flaps | |
| Roll back to SR-MPLS — labels return, SRv6 and BGP are torn down | |
| Teardown topology | |
