# Router Advertisements name the interface's prefixes (Prefix Information)

## Overview

An interface that sends Router Advertisements (`ipv6
router-advertisements send-advertisements true`) names in them the /64
of each of its global addresses, so that the hosts on it form their
own addresses (RFC 4861 §6.2.1, RFC 4862). That is what gets the hosts
behind a router an address from the prefix it was delegated (RFC 7084
L-2): `dhcpv6-options pd <id> interface <lan>` puts an address of the
prefix on the interface, and the advertisement names its /64.

- A prefix whose address never ends is advertised with RFC 4861's
- A renewal is told soon, not with the next periodic advertisement,
- A prefix that goes is advertised with both lifetimes zero (RFC 9096

Topology: s1 is the ISP side, a router with the small DHCPv6 server of
dhcpv6_client_pd.feature, which routes what it delegates, and the
prefix lan0 is numbered with by hand, to the client. r1 is zebra-rs:
a DHCPv6 WAN, and lan0 behind it, which advertises. h1 is a host on
lan0 with nothing configured: its kernel forms its addresses and its
default route from what r1 advertises.

Requires python3 on the host.

## Config Files

- r1.yaml: `address dhcpv6` and `pd 1 length 56 interface lan0 sla-id 1 address 1` on wan0; `2001:db8:aa::1/64` and `router-advertisements send-advertisements true` on lan0.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the delegating router, the advertising router and a host | |
| The advertisements name both prefixes of the interface | |
| A host with nothing configured gets its addresses and its route | |
| A renewal is told to the hosts soon | |
| A renewal with the same lifetimes still moves their end | |
| A prefix that is replaced is taken out of use on the hosts | |
| A configured address that is deleted takes its prefix out of use too | |
| A delegation that is given back takes its prefix out of use | |
| An interface that stops advertising names nothing | |
| Teardown topology | |
