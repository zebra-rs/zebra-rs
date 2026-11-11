# DHCPv4 client on a WAN interface (interface ipv4 address dhcp)

## Overview

`interface <if> ipv4 address dhcp` starts zebra-rs's own DHCP client
(the dhcpc task, docs/design/dhcp-client.md). Everything the lease gives
goes through the RIB: the address is a dynamic address with kernel
lifetimes (`show interface` tags it `dhcp`), and the default route is a
`D` route at distance 210, installed as `proto dhcp`.

Topology: s1 is the ISP side, a dnsmasq with one address to lease
(192.0.2.100, and 192.0.2.101 once it has been renumbered), itself as
the router, and 198.51.100.1 on its loopback: an address r1 reaches
only through the default route the lease gives.

dnsmasq's shortest lease is two minutes, which is what the server uses;
the expiry scenario waits that long. Requires dnsmasq and nft on the
host (tests/scripts/dhcp_server.sh).

## Config Files

- r1.yaml: `address dhcp` on wan0.
- r1-options.yaml: the same with `dhcp-options default-route-distance
  220` and `host-name edge1`.
- r1-id3.yaml: the same as r1.yaml with `dhcp-options client-id
  aa:bb:cc:dd:ee:03`.
- r1-no-default.yaml: the same as r1.yaml with `dhcp-options
  no-default-route`.
- r1-long-options.yaml: the same as r1-options.yaml with a `client-id`
  of 253 characters, a `vendor-class-id` of 100 and a `user-class` of
  50.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the server and a router with a DHCP WAN | |
| The lease gives the address, the default route and the server's options | |
| Renew by hand keeps the lease | |
| Release withdraws everything until the next renew | |
| A static address beside the lease is refused | |
| With another address ahead of it, the client still talks from the leased address | |
| A renewal the server refuses ends the lease at once | |
| A changed client-id gives the lease back and asks again as the new identity | |
| A reboot under another client-id releases the saved lease | |
| A release by hand while a saved lease is being given back leaves the interface released | |
| A restart of zebra-rs resumes the lease | |
| A restart without the default route takes the earlier run's away | |
| dhcp-options change the route's distance and the host name sent | |
| Deleting address dhcp releases the lease | |
| Options too long for one message field reach the server in the others | |
| A lease the server no longer renews expires | |
| Teardown topology | |
