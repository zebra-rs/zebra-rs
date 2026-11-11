# Name servers from Router Advertisements for the host (system name-server dhcp)

## Overview

Router Advertisements name name servers (RDNSS) and search domains
(DNSSL, RFC 8106). The RA host holds them with their lifetimes and
`show ipv6 nd interface` shows them; the host itself uses them only
where `system name-server dhcp <if>` says so (the resolver task,
docs/design/dhcp-client.md §13). They are then handed to
systemd-resolved as that link's DNS configuration: the ones heard of
last first, those of one option in the option's order (RFC 8106
§6.2), all behind those of a DHCP lease on the same interface. They
are taken back as their lifetimes end or the RA host stops.

No resolver is running here: the harness names a stand-in for
`resolvectl` to each daemon (tests/scripts/resolvectl_stub.sh), whose
`status` prints what it was told: `wan0 dns …`, `wan0 domain …`.

Topology: s1 sends exactly the Router Advertisements a scenario asks
for, from the pinned link-local fe80::1, and later runs a dnsmasq whose
DHCPv4 lease names 198.51.100.53 and example.com.

Requires dnsmasq and nft on the host (tests/scripts/dhcp_server.sh).

## Config Files

- r1.yaml: `ipv6 address autoconf` on wan0.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup a router that advertises a name server and an RA host | |
| Without the entry what the advertisements name is only shown | |
| The entry hands the advertised name server and domain to the host | |
| Newly advertised name servers go first, and an option keeps its order | |
| A lifetime of zero takes a name server away at once | |
| A name server whose lifetime runs out is taken away | |
| An advertisement that withdraws a name server and names it too leaves it in | |
| A DHCP lease's name server goes ahead of the advertised one | |
| The lease ending leaves the advertised name server | |
| Stopping the RA host takes what it gave back | |
| Teardown topology | |
