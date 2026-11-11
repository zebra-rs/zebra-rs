# DHCPv6 client on a WAN interface (interface ipv6 address dhcpv6)

## Overview

`interface <if> ipv6 address dhcpv6` starts zebra-rs's own DHCPv6
client on the interface (docs/design/dhcp-client.md §8). It leases an
address (an IA_NA) and puts it on the interface as a /128 that brings
no connected route: which prefixes are on-link is for a Router
Advertisement to say. So `address dhcpv6` runs the RA host too, for the
default route and the on-link prefixes, without forming a SLAAC
address.

`ipv6 dhcpv6-options parameters-only` asks the server for the other
configuration alone (DNS servers, the search list), with no address.

Topology: s1 is the ISP side, a dnsmasq that is both the DHCPv6 server,
with one address to lease, and the router that sends the Router
Advertisements, which give the prefix as on-link and as autonomous.
r1 is zebra-rs with a DHCPv6 WAN and nothing else configured there.
2001:db8:ffff::1 sits on s1's loopback: r1 reaches it only through the
default route the advertisements give, from the address the lease
gives.

dnsmasq's shortest lease is two minutes, which is what the server
uses. Requires dnsmasq on the host.

## Config Files

- r1.yaml: `ipv6 address dhcpv6` on wan0.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the server and a router with a DHCPv6 WAN | |
| The lease gives a /128 and the server's options | |
| The Router Advertisements give the routes, and no address | |
| Autoconf beside the lease adds a SLAAC address | |
| Renew by hand keeps the lease | |
| Release gives the address back until the next renew | |
| A restart keeps the address and confirms the lease | |
| Parameters only asks for no address | |
| An address again, and deleted configuration gives it back | |
| Teardown topology | |
