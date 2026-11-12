# A DHCPv6 lease's name servers for the host

## Overview

A DHCPv6 server names name servers and search domains (options 23 and
24, RFC 3646), with a lease or to a client that asked for the
parameters alone. `show dhcpv6 client leases` shows them, and the host
itself uses them: nothing but `address dhcpv6`, or `dhcpv6-options
parameters-only`, is configured for that (the resolver task,
docs/design/dhcp-client.md §13). They are handed to systemd-resolved
as the link's DNS configuration, behind those of a DHCPv4 lease on the
same interface and ahead of those its Router Advertisements name, and
taken back when the lease ends. `dhcpv6-options no-name-server` keeps
them from the host: they are then only shown, and what the other
sources name is none the worse for it.

No resolver is running here: the harness names a stand-in for
`resolvectl` to each daemon (tests/scripts/resolvectl_stub.sh), whose
`status` prints what it was told: `wan0 dns …`, `wan0 domain …`.

Topology: s1 is the ISP side, a dnsmasq that is the DHCPv6 server and
the router. What it tells a DHCPv6 client is not what it advertises,
so that the two can be told apart: the lease names 2001:db8:53::6 with
lease.example and corp.example, the Router Advertisements name
2001:db8:53::53 with example.com. One scenario starts a second
dnsmasq, whose DHCPv4 lease names 198.51.100.53 and example.com.

Requires dnsmasq on the host (tests/scripts/dhcp_server.sh).

## Config Files

- r1.yaml: `ipv6 address dhcpv6` on wan0, and nothing else.
- r1-no-name-server.yaml: the same with `dhcpv6-options
  no-name-server` and `ra-options no-name-server`.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the server and a router with a DHCPv6 WAN | |
| The lease hands its name servers to the host, ahead of the advertised ones | |
| Releasing the lease takes its name servers back, and a new lease gives them again | |
| dhcpv6-options no-name-server keeps the lease's back and leaves the advertised ones | |
| A lease taken under no-name-server is only shown | |
| Deleting no-name-server hands the held lease's name servers over | |
| A DHCPv4 lease's name server goes ahead of the DHCPv6 lease's | |
| A restart hands the resumed lease's name servers over again | |
| A restart under no-name-server resumes the lease and sets nothing | |
| Parameters only: name servers with no lease | |
| Deleted configuration takes the name servers back | |
| Teardown topology | |
