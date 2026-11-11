# A DHCP lease's name servers for the host (system name-server dhcp)

## Overview

A lease names name servers and search domains. `show dhcp client
leases` shows them; the host itself uses them only where
`system name-server dhcp <if>` says so (the resolver task,
docs/design/dhcp-client.md §13). They are then handed to
systemd-resolved as that link's DNS configuration, by running
`resolvectl`, and taken back when the lease ends or the entry is
deleted.

No resolver is running here, and none must be reached: every daemon
of the suite runs in a network namespace, from which `resolvectl`
would configure some other interface of the host. The harness names
a stand-in to each daemon (ZEBRA_RESOLVECTL,
tests/scripts/resolvectl_stub.sh). It keeps what it is told, per
namespace, and `status` prints it: `wan0 dns …`, `wan0 domain …`. Like
resolved it holds an interface's settings, not a name's: one deleted
and made again under the same name holds nothing. It can also be told
to fail (`break`), at once or after some seconds, to do what it is
asked and give no answer (`stall`), or to fail after dropping the list
it was to replace, as resolved does (`spoil`).

Topology: s1 is the ISP side, a dnsmasq with one address to lease. Its
lease names 198.51.100.53 as name server, example.com as domain name
and corp.example, lab.example as search list, until it is started
again with another name server and no search list.

Requires dnsmasq and nft on the host (tests/scripts/dhcp_server.sh).

## Config Files

- r1.yaml: `address dhcp` on wan0.
- r1-dns.yaml: the same with `system name-server dhcp wan0`.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the server and a router with a DHCP WAN | |
| Without the entry the lease's name servers are only shown | |
| The entry hands the lease's name servers and domains to the host | |
| Releasing the lease takes them back, and a new lease gives them again | |
| Other name servers at a renewal replace the first | |
| A resolver that is away gets them once it is back | |
| An error after the old name servers are gone does not leave them taken for held | |
| Name servers set by a command that got no answer are still taken back | |
| An interface made again is given its name servers again | |
| Deleting the entry takes them back and leaves the lease | |
| A restart hands the resumed lease's name servers over again | |
| Teardown topology | |
