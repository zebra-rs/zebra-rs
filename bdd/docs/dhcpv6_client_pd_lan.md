# Interfaces numbered from a delegated prefix (dhcpv6-options pd <id> interface)

## Overview

`interface <wan> ipv6 dhcpv6-options pd <id> interface <lan>` gives
`<lan>` an address in one /64 of the prefix delegated to `<wan>`
(docs/design/dhcp-client.md §8): the /64 its `sla-id` numbers, the
first when it has none, and in it the host part `address` names, or
one made from the interface's hardware address (EUI-64).

The address has the prefix's lifetimes and follows the lease: a
renewal moves its lifetimes, another prefix replaces it, and it goes
when the prefix is given back. Unlike a leased address it brings the
route to its /64, which is what takes that part of the prefix off the
unreachable route the whole of it has (dhcpv6_client_pd.feature).

Topology: s1 is the ISP side, a router with the small DHCPv6 server of
dhcpv6_client_pd.feature, which routes what it delegates to the
client. r1 is zebra-rs: a DHCPv6 WAN, and two interfaces behind it.
h1 is a host on the first, numbered by hand in the /64 that interface
gets; lan1 leads nowhere.

Requires python3 on the host.

## Config Files

- r1.yaml: `address dhcpv6` and `pd 1 length 56` on wan0, with `interface lan0 sla-id 1 address 1` and `interface lan1 sla-id 2`.
- r1_lan0.yaml: the same without lan1.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the delegating router, a router with two interfaces behind it, and a host | |
| Each interface gets its /64 of the prefix | |
| A host behind the router is reached through the prefix | |
| A link set down and up has its address again | |
| A renewal moves the lifetimes of the addresses | |
| Another prefix replaces the addresses | |
| The interfaces follow the configuration, and the prefix stays | |
| A restart keeps the addresses, and removes one that is configured no longer | |
| Deleted configuration gives the prefix back and takes the addresses | |
| Teardown topology | |
