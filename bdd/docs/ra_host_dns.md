# Name servers from Router Advertisements for the host

## Overview

Router Advertisements name name servers (RDNSS) and search domains
(DNSSL, RFC 8106). The RA host holds them with their lifetimes,
`show ipv6 nd interface` shows them, and the host itself uses them:
nothing but the RA host is configured for that (the resolver task,
docs/design/dhcp-client.md §13). They are handed to systemd-resolved
as the link's DNS configuration: the ones heard of last first, those
of one option in the option's order (RFC 8106 §6.2), all behind those
of a DHCP lease on the same interface. They are taken back as their
lifetimes end or the RA host stops. `ra-options no-name-server` keeps
an interface's advertised name servers from the host: they are then
only shown, and a lease's are none the worse for it.

No resolver is running here: the harness names a stand-in for
`resolvectl` to each daemon (tests/scripts/resolvectl_stub.sh), whose
`status` prints what it was told: `wan0 dns …`, `wan0 domain …`.

Topology: s1 sends exactly the Router Advertisements a scenario asks
for, from the pinned link-local fe80::1, and later runs a dnsmasq whose
DHCPv4 lease names 198.51.100.53 and example.com.

Requires dnsmasq and nft on the host (tests/scripts/dhcp_server.sh).

## Config Files

- r1.yaml: `ipv6 address autoconf` on wan0, and nothing else.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup a router that advertises a name server and an RA host | |
| The advertised name server and domain are handed to the host | |
| Newly advertised name servers go first, and an option keeps its order | |
| A lifetime of zero takes a name server away at once | |
| A name server whose lifetime runs out is taken away | |
| An advertisement that withdraws a name server and names it too leaves it in | |
| A DHCP lease's name server goes ahead of the advertised one | |
| ra-options no-name-server keeps the advertised ones back and leaves the lease's | |
| What is advertised under no-name-server is only shown | |
| Deleting no-name-server hands the held name servers over | |
| The lease ending leaves the advertised name servers | |
| Stopping the RA host takes what it gave back | |
| address autoconf committed with no-name-server keeps the advertised name server back from the start | |
| Teardown topology | |
