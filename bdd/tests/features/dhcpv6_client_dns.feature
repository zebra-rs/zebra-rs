@serial
@dhcpv6_client_dns
Feature: A DHCPv6 lease's name servers for the host

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

      s1 (dnsmasq) srv0 2001:db8:1::1/64 ──── wan0 (address dhcpv6) r1 (zebra-rs)

  Requires dnsmasq on the host (tests/scripts/dhcp_server.sh).

  Config files:
  - r1.yaml: `ipv6 address dhcpv6` on wan0, and nothing else.
  - r1-no-name-server.yaml: the same with `dhcpv6-options
    no-name-server` and `ra-options no-name-server`.

  Scenario: Setup the server and a router with a DHCPv6 WAN
    Given a clean test environment
    When I create namespace "s1"
    And I create namespace "r1"
    And I connect namespace "s1" interface "srv0" to namespace "r1" interface "wan0"
    # dnsmasq marks what it answers a DHCPv6 client with the tag
    # `dhcpv6`, and not what it advertises: the options under that tag
    # are the lease's alone.
    And I execute "tests/scripts/dhcp_server.sh dhcpv6_client_dns start6 srv0 2001:db8:1::1/64 2001:db8:1::100 2001:db8:1::100 120 --dhcp-option=tag:dhcpv6,option6:dns-server,[2001:db8:53::6] --dhcp-option=tag:dhcpv6,option6:domain-search,lease.example,corp.example" in namespace "s1"
    And I execute "tests/scripts/resolvectl_stub.sh reset" in namespace "r1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "DNS servers:  2001:db8:53::6"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "Search:       lease.example, corp.example"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should eventually contain "DNS servers: 2001:db8:53::53"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should contain "DNS search: example.com"

  Scenario: The lease hands its name servers to the host, ahead of the advertised ones
    Given the test topology exists
    # Nothing was configured but `address dhcpv6`. What DHCP names is
    # used first (RFC 8106 §5.3.1).
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8:53::6 2001:db8:53::53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain lease.example corp.example example.com"
    And daemon log in namespace "r1" should eventually contain "resolver: wan0: name servers 2001:db8:53::6 2001:db8:53::53, search lease.example corp.example example.com"

  Scenario: Releasing the lease takes its name servers back, and a new lease gives them again
    Given the test topology exists
    # The advertised ones are no lease's to take back.
    Then show command "release dhcpv6 interface wan0" in namespace "r1" should contain "Released the DHCPv6 lease on wan0"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "2001:db8:53::6"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "lease.example"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8:53::53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain example.com"
    And show command "renew dhcpv6 interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8:53::6 2001:db8:53::53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain lease.example corp.example example.com"

  Scenario: dhcpv6-options no-name-server keeps the lease's back and leaves the advertised ones
    Given the test topology exists
    # Each source has its own leaf. The lease is held as before, and
    # what it names is shown and no more.
    When I apply command "set interface wan0 ipv6 dhcpv6-options no-name-server" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "2001:db8:53::6"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "lease.example"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8:53::53"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "State:        bound"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "DNS servers:  2001:db8:53::6"
    And show command "show interface wan0" in namespace "r1" should eventually contain "inet6 2001:db8:1::100/128 noprefixroute dhcpv6 valid-lft"

  Scenario: A lease taken under no-name-server is only shown
    Given the test topology exists
    Then show command "release dhcpv6 interface wan0" in namespace "r1" should contain "Released"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        released"
    And show command "renew dhcpv6 interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "DNS servers:  2001:db8:53::6"
    # Time enough for a daemon that set them all the same to have done so.
    When I wait 3 seconds
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should not contain "2001:db8:53::6"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8:53::53"

  Scenario: Deleting no-name-server hands the held lease's name servers over
    Given the test topology exists
    When I apply command "delete interface wan0 ipv6 dhcpv6-options no-name-server" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8:53::6 2001:db8:53::53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain lease.example corp.example example.com"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "State:        bound"

  Scenario: A DHCPv4 lease's name server goes ahead of the DHCPv6 lease's
    Given the test topology exists
    # The same interface leases an IPv4 address too. The order is
    # systemd-networkd's: DHCPv4, DHCPv6, Router Advertisements. The
    # domain two of them name is given once, where the first names it.
    When I execute "tests/scripts/dhcp_server.sh dhcpv6_client_dns_v4 start srv0 192.0.2.1/24 192.0.2.100 192.0.2.100 120" in namespace "s1"
    And I apply command "set interface wan0 ipv4 address dhcp" in namespace "r1"
    Then show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 198.51.100.53 2001:db8:53::6 2001:db8:53::53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain example.com lease.example corp.example"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should not contain "corp.example example.com"
    # Without the IPv4 lease the other two are as they were.
    When I apply command "delete interface wan0 ipv4 address dhcp" in namespace "r1"
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8:53::6 2001:db8:53::53"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain lease.example corp.example example.com"
    When I execute "tests/scripts/dhcp_server.sh dhcpv6_client_dns_v4 stop" in namespace "s1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should contain "State:        bound"

  Scenario: A restart hands the resumed lease's name servers over again
    Given the test topology exists
    # The stand-in forgets, so that what it holds afterwards is what the
    # restarted daemon told it and not what the old one did.
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/resolvectl_stub.sh reset" in namespace "r1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then daemon log in namespace "r1" should eventually contain "dhcpv6 client: wan0: resumed 2001:db8:1::100"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8:53::6 2001:db8:53::53"

  Scenario: A restart under no-name-server resumes the lease and sets nothing
    Given the test topology exists
    # `address dhcpv6` and both `no-name-server` leaves arrive in one
    # commit, the lease is resumed from disk at once, and no name server
    # must reach the host even for a moment.
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/resolvectl_stub.sh reset" in namespace "r1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1-no-name-server.yaml" to namespace "r1"
    Then daemon log in namespace "r1" should eventually contain "dhcpv6 client: wan0: resumed 2001:db8:1::100"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "DNS servers:  2001:db8:53::6"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should eventually contain "DNS servers: 2001:db8:53::53"
    When I wait 3 seconds
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should not contain "wan0"

  Scenario: Parameters only: name servers with no lease
    Given the test topology exists
    # Without `address dhcpv6` the lease goes back, and the RA host
    # stops: nothing is left to name a name server.
    When I apply command "delete interface wan0 ipv6 dhcpv6-options no-name-server\ndelete interface wan0 ipv6 ra-options no-name-server\ndelete interface wan0 ipv6 address dhcpv6" in namespace "r1"
    Then show command "show interface wan0" in namespace "r1" should eventually not contain "2001:db8:1::100"
    When I wait 3 seconds
    Then command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should not contain "wan0"
    # What the server answers an Information-request is held with no
    # lease, and is the host's all the same. No Router Advertisement is
    # listened to for it.
    When I apply command "set interface wan0 ipv6 dhcpv6-options parameters-only" in namespace "r1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        informed"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 dns 2001:db8:53::6"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually contain "wan0 domain lease.example corp.example"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should not contain "2001:db8:53::53"
    And show command "show dhcpv6 client leases" in namespace "r1" should not contain "Address:"

  Scenario: Deleted configuration takes the name servers back
    Given the test topology exists
    When I apply command "delete interface wan0 ipv6 dhcpv6-options parameters-only" in namespace "r1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "DHCPv6 client is not configured"
    And command "tests/scripts/resolvectl_stub.sh status" in namespace "r1" should eventually not contain "wan0"
    And daemon log in namespace "r1" should eventually contain "resolver: wan0: name servers withdrawn"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_server.sh dhcpv6_client_dns stop" in namespace "s1"
    And I execute "tests/scripts/dhcp_server.sh dhcpv6_client_dns_v4 stop" in namespace "s1"
    And I execute "tests/scripts/resolvectl_stub.sh reset" in namespace "r1"
    And I delete namespace "r1"
    And I delete namespace "s1"
    Then the test environment should be clean
