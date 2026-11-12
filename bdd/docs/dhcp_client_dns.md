# A DHCP lease's name servers for the host

## Overview

A lease names name servers and search domains. `show dhcp client
leases` shows them, and the host itself uses them: nothing but
`address dhcp` is configured for that. They are handed to
systemd-resolved as the link's DNS configuration, by running
`resolvectl` (the resolver task, docs/design/dhcp-client.md §13), and
taken back when the lease ends. `dhcp-options no-name-server` keeps
an interface's name servers from the host: they are then only shown.

zebra-rs leaves them set when it stops, and keeps on disk which
interfaces hold some (`resolver.json`, beside the lease). The next run
sets what it learns again, the lease resumed from disk first of all,
and takes back what it has not learned when its wait for the sources
is over (`--leftover-sweep-time`): `no-name-server` set, or `address
dhcp` deleted, while zebra-rs was not running.

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

- r1.yaml: `address dhcp` on wan0, and nothing else.
- r1-no-name-server.yaml: the same with `dhcp-options no-name-server`.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the server and a router with a DHCP WAN | |
| The lease hands its name servers and domains to the host | |
| Releasing the lease takes them back, and a new lease gives them again | |
| Other name servers at a renewal replace the first | |
| A resolver that is away gets them once it is back | |
| An error after the old name servers are gone does not leave them taken for held | |
| Name servers set by a command that got no answer are still taken back | |
| An interface made again is given its name servers again | |
| no-name-server takes them back and leaves the lease | |
| A lease taken under no-name-server is only shown | |
| Deleting no-name-server hands the held lease's name servers over | |
| A restart hands the resumed lease's name servers over again | |
| A restart under no-name-server resumes the lease and sets nothing | |
| A restart keeps the name servers of the lease it resumes | |
| A restart under no-name-server takes back what the earlier run set | |
| A restart without the DHCP client takes back what the earlier run set | |
| Teardown topology | |
