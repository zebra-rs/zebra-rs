@serial
@ra_host_dns
Feature: Name servers from Router Advertisements for the host (system name-server dhcp)

  Router Advertisements name name servers (RDNSS) and search domains
  (DNSSL, RFC 8106). The RA host holds them with their lifetimes and
  `show ipv6 nd interface` shows them; the host itself uses them only
  where `system name-server dhcp <if>` says so (the resolver task,
  docs/design/dhcp-client.md §13). They are then handed to
  systemd-resolved as that link's DNS configuration, in the order they
  were heard, behind those of a DHCP lease on the same interface, and
  taken back as their lifetimes end or the RA host stops.

  No resolver is running here: the harness names a stand-in for
  `resolvectl` to each daemon (tests/scripts/resolvectl_stub.sh), whose
  `status` prints what it was told: `wan0 dns …`, `wan0 domain …`.

  Topology: s1 sends exactly the Router Advertisements a scenario asks
  for, from the pinned link-local fe80::1, and later runs a dnsmasq whose
  DHCPv4 lease names 198.51.100.53 and example.com.

      s1 (ra_sender.py, dnsmasq) srv0 fe80::1 ──── wan0 (autoconf) r1 (zebra-rs)

  Requires dnsmasq and nft on the host (tests/scripts/dhcp_server.sh).

  Config files:
  - r1.yaml: `ipv6 address autoconf` on wan0.

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

  Scenario: Without the entry what the advertisements name is only shown
    Given the test topology exists
    # Time enough for a daemon that set them unasked to have done so. The
    # next scenario has this same daemon reach the stand-in.
    When I wait 3 seconds
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should not contain "wan0"

  Scenario: The entry hands the advertised name server and domain to the host
    Given the test topology exists
    When I apply command "set system name-server dhcp wan0" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8::53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain example.com"
    And daemon log in namespace "r1" should eventually contain "resolver: wan0: name servers 2001:db8::53, search example.com"

  Scenario: Name servers are used in the order they were heard
    Given the test topology exists
    # Two more, the one with the higher address first: they go behind the
    # one already held and keep their own order (RFC 8106 §5.3.1), which
    # is not the order of their addresses.
    When I execute "tests/scripts/ra_sender.py srv0 --source fe80::1 --rdnss 2001:db8::99,600 --rdnss 2001:db8::11,600" in namespace "s1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8::53 2001:db8::99 2001:db8::11"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should contain "DNS servers: 2001:db8::53 2001:db8::99 2001:db8::11"

  Scenario: A lifetime of zero takes a name server away at once
    Given the test topology exists
    When I execute "tests/scripts/ra_sender.py srv0 --source fe80::1 --rdnss 2001:db8::99,0" in namespace "s1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8::53 2001:db8::11"

  Scenario: A name server whose lifetime runs out is taken away
    Given the test topology exists
    # Advertised again with three seconds to live. Nothing else of the
    # interface changes when they are over: no route, no address.
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

  Scenario: The lease ending leaves the advertised name server
    Given the test topology exists
    Then show command "release dhcp interface wan0" in namespace "r1" should contain "Released the DHCP lease on wan0"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8::53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain example.com"

  Scenario: Stopping the RA host takes what it gave back
    Given the test topology exists
    When I apply command "delete interface wan0 ipv6 address autoconf" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "wan0"
    And daemon log in namespace "r1" should eventually contain "resolver: wan0: name servers withdrawn"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should not contain "DNS servers"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_server.sh ra_host_dns stop" in namespace "s1"
    And I execute "tests/scripts/resolvectl_stub.sh reset" in namespace "r1"
    And I delete namespace "r1"
    And I delete namespace "s1"
    Then the test environment should be clean
