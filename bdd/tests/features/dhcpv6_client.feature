@serial
@dhcpv6_client
Feature: DHCPv6 client on a WAN interface (interface ipv6 address dhcpv6)

  `interface <if> ipv6 address dhcpv6` starts zebra-rs's own DHCPv6
  client on the interface (docs/design/dhcp-client.md §8). It leases an
  address (an IA_NA) and puts it on the interface as a /128 that brings
  no connected route: which prefixes are on-link is for a Router
  Advertisement to say. So `address dhcpv6` runs the RA host too, for the
  default route and the on-link prefixes, without forming a SLAAC
  address.

  `ipv6 dhcpv6-options parameters-only` asks the server for the other
  configuration alone (DNS servers, the search list), with no address.

  Topology: s1 is the ISP side, a dnsmasq that is both the DHCPv6 server,
  with one address to lease, and the router that sends the Router
  Advertisements, which give the prefix as on-link and as autonomous.
  r1 is zebra-rs with a DHCPv6 WAN and nothing else configured there.
  2001:db8:ffff::1 sits on s1's loopback: r1 reaches it only through the
  default route the advertisements give, from the address the lease
  gives.

      s1 (dnsmasq) srv0 2001:db8:1::1/64 ──── wan0 (address dhcpv6) r1 (zebra-rs)
         lo 2001:db8:ffff::1/128

  dnsmasq's shortest lease is two minutes, which is what the server
  uses. Requires dnsmasq on the host.

  Config files:
  - r1.yaml: `ipv6 address dhcpv6` on wan0.

  Scenario: Setup the server and a router with a DHCPv6 WAN
    Given a clean test environment
    When I create namespace "s1"
    And I create namespace "r1"
    And I connect namespace "s1" interface "srv0" to namespace "r1" interface "wan0"
    And I execute "tests/scripts/dhcp_server.sh dhcpv6_client start6 srv0 2001:db8:1::1/64 2001:db8:1::100 2001:db8:1::100 120" in namespace "s1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"

  Scenario: The lease gives a /128 and the server's options
    Given the test topology exists
    Then show command "show dhcpv6 client leases" in namespace "r1" should contain "Address:      2001:db8:1::100/128 preferred"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "DUID:         00:01:00:01:"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "Server:       fe80::"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "DNS servers:  2001:db8:53::53"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "Search:       example.com"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "Renew in:"
    And show command "show interface wan0" in namespace "r1" should eventually contain "inet6 2001:db8:1::100/128 noprefixroute dhcpv6 valid-lft"
    And show command "show dhcpv6 client leases interface wan0" in namespace "r1" should contain "State:        bound"
    And show command "show dhcpv6 client leases interface lo" in namespace "r1" should contain "No DHCPv6 client on lo"
    And command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client/dnsmasq.log" in namespace "s1" should eventually contain "DHCPREPLY(srv0) 2001:db8:1::100"

  Scenario: The Router Advertisements give the routes, and no address
    Given the test topology exists
    # The RA host runs for the lease: the default route, and the prefix
    # on-link because the advertisement says so, not because an address
    # in it is on the interface.
    Then show command "show ipv6 nd interface wan0" in namespace "r1" should eventually contain "RA host: enabled (dhcpv6)"
    And show command "show ipv6 route" in namespace "r1" should eventually contain "::/0 [210/0] via fe80::"
    And show command "show ipv6 route" in namespace "r1" should eventually contain "2001:db8:1::/64 [210/0] via ::, wan0"
    And command "ip -6 route show 2001:db8:1::/64" in namespace "r1" should eventually contain "dev wan0 proto ra"
    And ping from "r1" to "2001:db8:ffff::1" should eventually succeed
    # The prefix is advertised as autonomous, and still no SLAAC address
    # comes of `address dhcpv6`: the lease is the address.
    And show command "show ipv6 nd interface wan0" in namespace "r1" should contain "2001:db8:1::/64 valid"
    And show command "show interface wan0" in namespace "r1" should not contain "slaac"

  Scenario: Autoconf beside the lease adds a SLAAC address
    Given the test topology exists
    When I apply command "set interface wan0 ipv6 address autoconf" in namespace "r1"
    Then show command "show ipv6 nd interface wan0" in namespace "r1" should eventually contain "RA host: enabled (autoconf, dhcpv6)"
    And show command "show interface wan0" in namespace "r1" should eventually contain "/64 noprefixroute slaac valid-lft"
    And show command "show interface wan0" in namespace "r1" should contain "inet6 2001:db8:1::100/128 noprefixroute dhcpv6 valid-lft"
    # Without it again, its address goes; the lease and the RA host's
    # routes stay.
    When I apply command "delete interface wan0 ipv6 address autoconf" in namespace "r1"
    Then show command "show interface wan0" in namespace "r1" should eventually not contain "slaac"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should contain "RA host: enabled (dhcpv6)"
    And show command "show interface wan0" in namespace "r1" should contain "inet6 2001:db8:1::100/128 noprefixroute dhcpv6 valid-lft"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "State:        bound"
    And show command "show ipv6 route" in namespace "r1" should contain "::/0 [210/0] via fe80::"
    And ping from "r1" to "2001:db8:ffff::1" should succeed

  Scenario: Renew by hand keeps the lease
    Given the test topology exists
    Then show command "renew dhcpv6 interface wan0" in namespace "r1" should contain "Renewing the DHCPv6 lease on wan0"
    And command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client/dnsmasq.log" in namespace "s1" should eventually contain "DHCPRENEW(srv0)"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "renew dhcpv6 interface lo" in namespace "r1" should contain "No DHCPv6 client on lo"
    And ping from "r1" to "2001:db8:ffff::1" should succeed

  Scenario: Release gives the address back until the next renew
    Given the test topology exists
    Then show command "release dhcpv6 interface wan0" in namespace "r1" should contain "Released the DHCPv6 lease on wan0"
    And command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client/dnsmasq.log" in namespace "s1" should eventually contain "DHCPRELEASE(srv0)"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        released"
    And show command "show interface wan0" in namespace "r1" should eventually not contain "2001:db8:1::100"
    And show command "renew dhcpv6 interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show interface wan0" in namespace "r1" should eventually contain "inet6 2001:db8:1::100/128 noprefixroute dhcpv6 valid-lft"
    And ping from "r1" to "2001:db8:ffff::1" should eventually succeed

  Scenario: A restart keeps the address and confirms the lease
    Given the test topology exists
    # The kernel keeps the address by its lifetime while zebra-rs is
    # away. Back, the client takes the lease from disk, uses it at once
    # and asks whether it is still right for the link.
    When I stop zebra-rs in namespace "r1"
    Then command "ip -6 addr show dev wan0" in namespace "r1" should eventually contain "2001:db8:1::100/128"
    When I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then daemon log in namespace "r1" should eventually contain "dhcpv6 client: wan0: resumed 2001:db8:1::100"
    And command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client/dnsmasq.log" in namespace "s1" should eventually contain "DHCPCONFIRM(srv0)"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show interface wan0" in namespace "r1" should eventually contain "inet6 2001:db8:1::100/128 noprefixroute dhcpv6 valid-lft"
    And ping from "r1" to "2001:db8:ffff::1" should eventually succeed

  Scenario: Parameters only asks for no address
    Given the test topology exists
    # Not both on one interface: the commit is refused and the lease is
    # as it was.
    Then applying command "set interface wan0 ipv6 dhcpv6-options parameters-only" in namespace "r1" should be rejected with "interface wan0 ipv6: dhcpv6-options parameters-only asks for no address and cannot be combined with address dhcpv6; delete one or the other"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "State:        bound"
    # Without `address dhcpv6` the lease goes back, and with it the RA
    # host and its routes.
    When I apply command "delete interface wan0 ipv6 address dhcpv6" in namespace "r1"
    Then show command "show interface wan0" in namespace "r1" should eventually not contain "2001:db8:1::100"
    And show command "show ipv6 route" in namespace "r1" should eventually not contain "::/0"
    # The answer to an Information-request comes over the link alone.
    When I apply command "set interface wan0 ipv6 dhcpv6-options parameters-only" in namespace "r1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        informed"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "DNS servers:  2001:db8:53::53"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "Search:       example.com"
    And show command "show dhcpv6 client leases" in namespace "r1" should not contain "Address:"
    And show command "show dhcpv6 client leases" in namespace "r1" should not contain "IAID:"
    And command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client/dnsmasq.log" in namespace "s1" should eventually contain "DHCPINFORMATION-REQUEST(srv0)"
    And show command "show interface wan0" in namespace "r1" should not contain "2001:db8:1::100"

  Scenario: An address again, and deleted configuration gives it back
    Given the test topology exists
    When I apply command "delete interface wan0 ipv6 dhcpv6-options parameters-only" in namespace "r1"
    And I apply command "set interface wan0 ipv6 address dhcpv6" in namespace "r1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show interface wan0" in namespace "r1" should eventually contain "inet6 2001:db8:1::100/128 noprefixroute dhcpv6 valid-lft"
    And ping from "r1" to "2001:db8:ffff::1" should eventually succeed
    When I apply command "delete interface wan0 ipv6 address dhcpv6" in namespace "r1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "DHCPv6 client is not configured"
    And show command "show interface wan0" in namespace "r1" should eventually not contain "2001:db8:1::100"
    And show command "show ipv6 route" in namespace "r1" should eventually not contain "::/0"
    And daemon log in namespace "r1" should eventually contain "dhcpv6 client: wan0: stopped"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_server.sh dhcpv6_client stop" in namespace "s1"
    And I delete namespace "r1"
    And I delete namespace "s1"
    Then the test environment should be clean
