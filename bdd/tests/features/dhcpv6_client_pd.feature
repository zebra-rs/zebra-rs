@serial
@dhcpv6_client_pd
Feature: DHCPv6 prefix delegation on a WAN interface (ipv6 dhcpv6-options pd)

  `interface <if> ipv6 dhcpv6-options pd <id>` has zebra-rs's DHCPv6
  client ask for a delegated prefix (an IA_PD under that IAID), alone or
  beside the address `ipv6 address dhcpv6` asks for
  (docs/design/dhcp-client.md §8). `pd <id> length <n>` is a hint: the
  server delegates what it sees fit.

  A delegated prefix is this router's to hand out, and until it does,
  nothing in it is in use. So each one gets a discard route (RFC 7084
  WPD-5): a packet for an unused part of it must not follow the default
  route back to the router that delegated it, which would send it here
  again. Like `address dhcpv6`, `pd` runs the RA host, for the default
  route.

  Topology: s1 is the ISP side, a router. It runs a small DHCPv6 server
  (tests/scripts/dhcpv6_server.py: dnsmasq delegates no prefix) with one
  address to lease and a prefix for each of the IA_PDs 1 and 2, and it
  routes what it delegates to the client, as a delegating router does.
  Its one Router Advertisement gives r1 the default route. r1 is
  zebra-rs with a DHCPv6 WAN and nothing else.

      s1 (dhcpv6_server.py) srv0 fe80::1 ──── wan0 (address dhcpv6, pd 1) r1 (zebra-rs)
         lo 2001:db8:ffff::1/128
         pd 1 = 2001:db8:100::/56, pd 2 = 2001:db8:200::/56

  s1 also routes 2001:db8:300::/56 to r1, which the server never
  delegates: r1 holds no route for it, so it shows what becomes of a
  packet for a prefix that has no discard route.

  Requires python3 on the host.

  Config files:
  - r1.yaml: `ipv6 address dhcpv6` and `ipv6 dhcpv6-options pd 1 length 56` on wan0.

  Scenario: Setup the delegating router and a router that asks for a prefix
    Given a clean test environment
    When I create namespace "s1"
    And I create namespace "r1"
    And I connect namespace "s1" interface "srv0" to namespace "r1" interface "wan0"
    And I execute "ip addr add fe80::1/64 dev srv0 nodad" in namespace "s1"
    And I execute "ip link set lo up" in namespace "s1"
    And I execute "ip -6 addr add 2001:db8:ffff::1/128 dev lo" in namespace "s1"
    And I execute "sysctl -q -w net.ipv6.conf.all.forwarding=1" in namespace "s1"
    And I execute "tests/scripts/dhcpv6_server.py dhcpv6_client_pd start srv0 --address 2001:db8:1::100 --pd 1=2001:db8:100::/56 --pd 2=2001:db8:200::/56 --dns 2001:db8:53::53 --route --route-also 2001:db8:300::/56" in namespace "s1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"

  Scenario: The lease gives the address and the prefix
    Given the test topology exists
    Then show command "show dhcpv6 client leases" in namespace "r1" should contain "Address:      2001:db8:1::100/128 preferred"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "Prefix:       2001:db8:100::/56 preferred"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "(pd 1)"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "Renew in:"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "DNS servers:  2001:db8:53::53"
    And show command "show interface wan0" in namespace "r1" should eventually contain "inet6 2001:db8:1::100/128 noprefixroute dhcpv6 valid-lft"
    # The hint went out with the Solicit, and both came in one exchange.
    And command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client_pd/server.log" in namespace "s1" should eventually contain "ia_pd 1 ::/56"
    And command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client_pd/server.log" in namespace "s1" should eventually contain "REPLY 2001:db8:1::100 2001:db8:100::/56"
    And daemon log in namespace "r1" should eventually contain "dhcpv6 client: wan0: bound 2001:db8:1::100, 2001:db8:100::/56 from fe80::"
    # `pd` asks for the RA host as `address dhcpv6` does.
    And show command "show ipv6 nd interface wan0" in namespace "r1" should eventually contain "RA host: enabled (dhcpv6, pd)"

  Scenario: The prefix is held by a discard route
    Given the test topology exists
    Then show command "show ipv6 route" in namespace "r1" should eventually contain "2001:db8:100::/56 [210/0]"
    And command "ip -6 route show 2001:db8:100::/56" in namespace "r1" should eventually contain "blackhole 2001:db8:100::/56"
    And command "ip -6 route show 2001:db8:100::/56" in namespace "r1" should eventually contain "proto dhcp"
    # s1 routes the prefix here, and here the default route points back
    # at s1. 2001:db8:300::/56 shows what that makes of a packet for an
    # address nobody has: s1 routes it here too, nothing holds it here,
    # and it goes round until its hop limit runs out.
    When I execute "tests/scripts/ra_sender.py srv0 --source fe80::1" in namespace "s1"
    Then show command "show ipv6 route" in namespace "r1" should eventually contain "::/0 [210/0] via fe80::1"
    And command "ip -6 route show 2001:db8:100::/56" in namespace "s1" should eventually contain "via fe80::"
    And command "ip -6 route show 2001:db8:300::/56" in namespace "s1" should eventually contain "via fe80::"
    And command "tests/scripts/ping6_once.sh 2001:db8:300::1 2001:db8:ffff::1" in namespace "s1" should eventually contain "Time exceeded"
    # Not so in the delegated prefix: the packet ends here.
    And command "tests/scripts/ping6_once.sh 2001:db8:100::1 2001:db8:ffff::1" in namespace "s1" should not contain "exceeded"

  Scenario: Renew by hand keeps the prefix
    Given the test topology exists
    Then show command "renew dhcpv6 interface wan0" in namespace "r1" should contain "Renewing the DHCPv6 lease on wan0"
    And command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client_pd/server.log" in namespace "s1" should eventually contain "RENEW ia_na"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "Prefix:       2001:db8:100::/56 preferred"
    And command "ip -6 route show 2001:db8:100::/56" in namespace "r1" should eventually contain "blackhole 2001:db8:100::/56"

  Scenario: A restart keeps the prefix and its route
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then daemon log in namespace "r1" should eventually contain "dhcpv6 client: wan0: resumed 2001:db8:1::100, 2001:db8:100::/56"
    # A Confirm says nothing of a prefix (RFC 8415 §18.2.12): with one
    # held, the lease is verified by a Rebind.
    And command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client_pd/server.log" in namespace "s1" should eventually contain "REBIND ia_na"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "Prefix:       2001:db8:100::/56 preferred"
    And show command "show ipv6 route" in namespace "r1" should eventually contain "2001:db8:100::/56 [210/0]"
    And command "ip -6 route show 2001:db8:100::/56" in namespace "r1" should eventually contain "blackhole 2001:db8:100::/56"

  Scenario: Another delegation is asked for as a new client
    Given the test topology exists
    # What a client asks for is who it is to the server: the lease goes
    # back, and the address and both prefixes are asked for together.
    When I apply command "set interface wan0 ipv6 dhcpv6-options pd 2" in namespace "r1"
    Then command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client_pd/server.log" in namespace "s1" should eventually contain "RELEASE ia_na"
    And command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client_pd/server.log" in namespace "s1" should eventually contain "REPLY 2001:db8:1::100 2001:db8:100::/56 2001:db8:200::/56"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "2001:db8:200::/56 preferred"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "(pd 2)"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "Prefix:       2001:db8:100::/56 preferred"
    And command "ip -6 route show 2001:db8:200::/56" in namespace "r1" should eventually contain "blackhole 2001:db8:200::/56"
    And command "ip -6 route show 2001:db8:100::/56" in namespace "r1" should eventually contain "blackhole 2001:db8:100::/56"
    # A delegation the server has nothing for is asked for all the same,
    # and shown as holding nothing.
    When I apply command "set interface wan0 ipv6 dhcpv6-options pd 7" in namespace "r1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "none (pd 7)"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "2001:db8:200::/56 preferred"
    When I apply command "delete interface wan0 ipv6 dhcpv6-options pd 7" in namespace "r1"
    And I apply command "delete interface wan0 ipv6 dhcpv6-options pd 2" in namespace "r1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually not contain "(pd 2)"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "Prefix:       2001:db8:100::/56 preferred"
    And command "ip -6 route show 2001:db8:200::/56" in namespace "r1" should eventually not contain "blackhole"
    And command "ip -6 route show 2001:db8:100::/56" in namespace "r1" should eventually contain "blackhole 2001:db8:100::/56"

  Scenario: A prefix without an address
    Given the test topology exists
    # Not with `parameters-only`, which asks for nothing to lease.
    Then applying command "set interface wan0 ipv6 dhcpv6-options parameters-only" in namespace "r1" should be rejected with "cannot be combined with"
    When I apply command "delete interface wan0 ipv6 address dhcpv6" in namespace "r1"
    Then show command "show interface wan0" in namespace "r1" should eventually not contain "2001:db8:1::100"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "Prefix:       2001:db8:100::/56 preferred"
    And show command "show dhcpv6 client leases" in namespace "r1" should not contain "Address:"
    And show command "show dhcpv6 client leases" in namespace "r1" should not contain "IAID:"
    # The RA host stays for the prefix alone, and its default route.
    And show command "show ipv6 nd interface wan0" in namespace "r1" should eventually contain "RA host: enabled (pd)"
    And command "ip -6 route show 2001:db8:100::/56" in namespace "r1" should eventually contain "blackhole 2001:db8:100::/56"

  Scenario: Deleted configuration gives the prefix back
    Given the test topology exists
    When I apply command "delete interface wan0 ipv6 dhcpv6-options pd 1" in namespace "r1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "DHCPv6 client is not configured"
    And command "ip -6 route show 2001:db8:100::/56" in namespace "r1" should eventually not contain "blackhole"
    And show command "show ipv6 route" in namespace "r1" should eventually not contain "2001:db8:100::/56"
    And command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client_pd/server.log" in namespace "s1" should eventually contain "RELEASE ia_pd 1 2001:db8:100::/56"
    # The delegating router routes it here no longer.
    And command "ip -6 route show 2001:db8:100::/56" in namespace "s1" should eventually not contain "via fe80::"
    And daemon log in namespace "r1" should eventually contain "dhcpv6 client: wan0: stopped"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcpv6_server.py dhcpv6_client_pd stop" in namespace "s1"
    And I delete namespace "r1"
    And I delete namespace "s1"
    Then the test environment should be clean
