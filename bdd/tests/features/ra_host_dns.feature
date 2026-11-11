@serial
@ra_host_dns
Feature: Name servers from Router Advertisements for the host

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

      s1 (ra_sender.py, dnsmasq) srv0 fe80::1 ──── wan0 (autoconf) r1 (zebra-rs)

  Requires dnsmasq and nft on the host (tests/scripts/dhcp_server.sh).

  Config files:
  - r1.yaml: `ipv6 address autoconf` on wan0, and nothing else.

  Scenario: Setup a router that advertises a name server and an RA host
    Given a clean test environment
    When I create namespace "s1"
    And I create namespace "r1"
    And I connect namespace "s1" interface "srv0" to namespace "r1" interface "wan0"
    And I execute "ip addr add fe80::1/64 dev srv0 nodad" in namespace "s1"
    And I execute "tests/scripts/resolvectl_stub.sh reset" in namespace "r1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then show command "show ipv6 nd interface wan0" in namespace "r1" should eventually contain "RA host: enabled (autoconf)"
    When I execute "tests/scripts/ra_sender.py srv0 --source fe80::1 --rdnss 2001:db8::53,600 --dnssl example.com,600" in namespace "s1"
    Then show command "show ipv6 nd interface wan0" in namespace "r1" should eventually contain "DNS servers: 2001:db8::53"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should contain "DNS search: example.com"

  Scenario: The advertised name server and domain are handed to the host
    Given the test topology exists
    # Nothing was configured but `address autoconf`.
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8::53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain example.com"
    And daemon log in namespace "r1" should eventually contain "resolver: wan0: name servers 2001:db8::53, search example.com"

  Scenario: Newly advertised name servers go first, and an option keeps its order
    Given the test topology exists
    # One option naming two servers the host has not heard of, the one
    # with the higher address first, and one naming two domains. RFC 8106
    # §6.2 puts what is new ahead of what was held, and keeps the order
    # an option gives: neither is the order of the addresses.
    When I execute "tests/scripts/ra_sender.py srv0 --source fe80::1 --rdnss 2001:db8::99+2001:db8::11,600 --dnssl new.example+more.example,600" in namespace "s1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8::99 2001:db8::11 2001:db8::53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain new.example more.example example.com"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should contain "DNS servers: 2001:db8::99 2001:db8::11 2001:db8::53"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should contain "DNS search: new.example more.example example.com"

  Scenario: A lifetime of zero takes a name server away at once
    Given the test topology exists
    When I execute "tests/scripts/ra_sender.py srv0 --source fe80::1 --rdnss 2001:db8::99,0 --dnssl new.example+more.example,0" in namespace "s1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8::11 2001:db8::53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "new.example"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain example.com"

  Scenario: A name server whose lifetime runs out is taken away
    Given the test topology exists
    # Advertised again with three seconds to live, which leaves it where
    # it stands. Nothing else of the interface changes when they are
    # over: no route, no address.
    When I execute "tests/scripts/ra_sender.py srv0 --source fe80::1 --rdnss 2001:db8::11,3" in namespace "s1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "2001:db8::11"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8::53"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should contain "DNS servers: 2001:db8::53"

  Scenario: A DHCP lease's name server goes ahead of the advertised one
    Given the test topology exists
    # The same interface leases an IPv4 address, in another task. What
    # DHCP names is used first (RFC 8106 §5.3.1), and the domain both
    # name is given once.
    When I execute "tests/scripts/dhcp_server.sh ra_host_dns start srv0 192.0.2.1/24 192.0.2.100 192.0.2.100 120" in namespace "s1"
    And I apply command "set interface wan0 ipv4 address dhcp" in namespace "r1"
    Then show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.53 2001:db8::53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain example.com"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should not contain "example.com example.com"

  Scenario: ra-options no-name-server keeps the advertised ones back and leaves the lease's
    Given the test topology exists
    # Each source has its own leaf: the lease's name server stays the
    # host's, and what the advertisements named is shown and no more.
    When I apply command "set interface wan0 ipv6 ra-options no-name-server" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "2001:db8::53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.53"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should contain "DNS servers: 2001:db8::53"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should contain "default route distance 210, no-name-server"

  Scenario: What is advertised under no-name-server is only shown
    Given the test topology exists
    When I execute "tests/scripts/ra_sender.py srv0 --source fe80::1 --rdnss 2001:db8::77,600" in namespace "s1"
    Then show command "show ipv6 nd interface wan0" in namespace "r1" should eventually contain "DNS servers: 2001:db8::77 2001:db8::53"
    # Time enough for a daemon that set them all the same to have done so.
    When I wait 3 seconds
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should not contain "2001:db8::"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.53"

  Scenario: Deleting no-name-server hands the held name servers over
    Given the test topology exists
    When I apply command "delete interface wan0 ipv6 ra-options no-name-server" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.53 2001:db8::77 2001:db8::53"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should not contain "no-name-server"

  Scenario: The lease ending leaves the advertised name servers
    Given the test topology exists
    Then show command "release dhcp interface wan0" in namespace "r1" should contain "Released the DHCP lease on wan0"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8::77 2001:db8::53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain example.com"

  Scenario: Stopping the RA host takes what it gave back
    Given the test topology exists
    When I apply command "delete interface wan0 ipv6 address autoconf" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "wan0"
    And daemon log in namespace "r1" should eventually contain "resolver: wan0: name servers withdrawn"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should not contain "DNS servers"

  Scenario: address autoconf committed with no-name-server keeps the advertised name server back from the start
    Given the test topology exists
    # Both leaves in one commit, on the interface whose RA host the last
    # scenario stopped. The leaves of a commit take effect together, so
    # the host starts with the option in force: the name server an
    # advertisement names after that is shown, and the stand-in, which
    # has forgotten what it was told before, is never told of it.
    When I execute "tests/scripts/resolvectl_stub.sh reset" in namespace "r1"
    And I apply command "set interface wan0 ipv6 address autoconf\nset interface wan0 ipv6 ra-options no-name-server" in namespace "r1"
    Then show command "show ipv6 nd interface wan0" in namespace "r1" should eventually contain "RA host: enabled (autoconf)"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should contain "no-name-server"
    When I execute "tests/scripts/ra_sender.py srv0 --source fe80::1 --rdnss 2001:db8::53,600" in namespace "s1"
    Then show command "show ipv6 nd interface wan0" in namespace "r1" should eventually contain "DNS servers: 2001:db8::53"
    When I wait 2 seconds
    Then command "tests/scripts/resolvectl_stub.sh history" in namespace "r1" should not contain "2001:db8::53"
    # And both taken back in one commit: the host stops, and what it
    # held is not handed over on the way out.
    When I apply command "delete interface wan0 ipv6 ra-options no-name-server\ndelete interface wan0 ipv6 address autoconf" in namespace "r1"
    Then show command "show ipv6 nd interface wan0" in namespace "r1" should eventually not contain "RA host: enabled"
    And command "tests/scripts/resolvectl_stub.sh history" in namespace "r1" should not contain "2001:db8::53"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_server.sh ra_host_dns stop" in namespace "s1"
    And I execute "tests/scripts/resolvectl_stub.sh reset" in namespace "r1"
    And I delete namespace "r1"
    And I delete namespace "s1"
    Then the test environment should be clean
