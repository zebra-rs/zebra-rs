# DHCPv6 prefix delegation on a WAN interface (ipv6 dhcpv6-options pd)

## Overview

`interface <if> ipv6 dhcpv6-options pd <id>` has zebra-rs's DHCPv6
client ask for a delegated prefix (an IA_PD under that IAID), alone or
beside the address `ipv6 address dhcpv6` asks for
(docs/design/dhcp-client.md §8). `pd <id> length <n>` is a hint: the
server delegates what it sees fit.

A delegated prefix is this router's to hand out, and until it does,
nothing in it is in use. So each one gets an unreachable route (RFC
7084 WPD-5): a packet for an unused part of it must not follow the
default route back to the router that delegated it, which would send
it here again. It ends here, and its sender is told so with an ICMPv6
Destination Unreachable. Like `address dhcpv6`, `pd` runs the RA host,
for the default route.

Topology: s1 is the ISP side, a router. It runs a small DHCPv6 server
(tests/scripts/dhcpv6_server.py: dnsmasq delegates no prefix) with one
address to lease and a prefix for each of the IA_PDs 1 and 2, and it
routes what it delegates to the client, as a delegating router does.
Its one Router Advertisement gives r1 the default route. r1 is
zebra-rs with a DHCPv6 WAN and nothing else.

s1 also routes 2001:db8:300::/56 to r1, which the server never
delegates: r1 holds no route for it, so it shows what becomes of a
packet for a prefix that has no such route.

Requires python3 on the host.

## Config Files

- r1.yaml: `ipv6 address dhcpv6` and `ipv6 dhcpv6-options pd 1 length 56` on wan0.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the delegating router and a router that asks for a prefix | |
| The lease gives the address and the prefix | |
| The prefix is held by an unreachable route | |
| Renew by hand keeps the prefix | |
| A restart keeps the prefix and its route | |
| A blackhole route an earlier version left becomes the unreachable one | |
| A restart that asks for no prefix takes the earlier run's route away | |
| Another delegation is asked for as a new client | |
| A prefix without an address | |
| Deleted configuration gives the prefix back | |
| Teardown topology | |
