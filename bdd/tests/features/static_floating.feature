@static_floating
Feature: Floating static route (nexthops at different metrics)
  A static route whose nexthops carry different metrics is a floating
  route: one kernel route per nexthop, each at its own metric, so the
  kernel forwards through the lowest one that is there and falls back by
  itself. zebra-rs keeps exactly the members whose gateway resolves in
  the kernel — a member that is down neither blocks the others nor is
  retried, one whose gateway stops resolving while its link stays up is
  withdrawn, and either comes back when it can — and `show ip route`
  marks each member installed on its own.

  The primary is left at the default metric, 0. IPv6 has no kernel
  priority 0 (Linux installs such a route at 1024, which would rank it
  behind the backup at 10), so there the primary goes in at priority 1.

  Both gateways answer for 203.0.113.1 and 2001:db8:113::1, so a ping
  from z1 succeeds through whichever member the kernel is using; only
  g1 answers for 203.0.113.101 and 2001:db8:113::101, so that ping
  succeeds only while the kernel prefers the primary.

  ```
   g1  192.0.2.1    2001:db8:a::1 ── wan0 ┐
                                           z1   203.0.113.0/24, 2001:db8:113::/48
   g2  198.51.100.1 2001:db8:b::1 ── wan1 ┘    primary via g1, backup via g2
  ```

  Scenario: Build topology and install both members
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "g1"
    And I create namespace "g2"
    And I connect namespace "z1" interface "wan0" to namespace "g1" interface "eth0"
    And I connect namespace "z1" interface "wan1" to namespace "g2" interface "eth0"
    And I make namespace "g1" interface "lo" up
    And I make namespace "g2" interface "lo" up
    # A gateway's link is taken down below; keep its IPv6 address through it.
    And I execute "sysctl -q -w net.ipv6.conf.eth0.keep_addr_on_down=1" in namespace "g1"
    And I execute "sysctl -q -w net.ipv6.conf.eth0.keep_addr_on_down=1" in namespace "g2"
    And I add address "192.0.2.1/24" to interface "eth0" in namespace "g1"
    And I add address "2001:db8:a::1/64" to interface "eth0" in namespace "g1"
    And I add address "203.0.113.1/32" to interface "lo" in namespace "g1"
    And I add address "2001:db8:113::1/128" to interface "lo" in namespace "g1"
    And I add address "203.0.113.101/32" to interface "lo" in namespace "g1"
    And I add address "2001:db8:113::101/128" to interface "lo" in namespace "g1"
    And I add address "198.51.100.1/24" to interface "eth0" in namespace "g2"
    And I add address "2001:db8:b::1/64" to interface "eth0" in namespace "g2"
    And I add address "203.0.113.1/32" to interface "lo" in namespace "g2"
    And I add address "2001:db8:113::1/128" to interface "lo" in namespace "g2"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"
    Then kernel route "203.0.113.0/24" in namespace "z1" should eventually contain "via 192.0.2.1 dev wan0"
    And kernel route "203.0.113.0/24" in namespace "z1" should eventually contain "via 198.51.100.1 dev wan1 proto zebra metric 10"
    And kernel route "2001:db8:113::/48" in namespace "z1" should eventually contain "via 2001:db8:a::1 dev wan0 proto zebra metric 1 onlink"
    And kernel route "2001:db8:113::/48" in namespace "z1" should eventually contain "via 2001:db8:b::1 dev wan1 proto zebra metric 10 onlink"
    And show command "show ip route" in namespace "z1" should eventually contain "*> 203.0.113.0/24 [1/0] via 192.0.2.1, wan0"
    And show command "show ip route" in namespace "z1" should eventually contain "*?"
    And show command "show ipv6 route" in namespace "z1" should eventually contain "*> 2001:db8:113::/48 [1/0] via 2001:db8:a::1, wan0"
    And show command "show ipv6 route" in namespace "z1" should eventually contain "*?"
    And ping from "z1" to "203.0.113.1" should eventually succeed
    And ping from "z1" to "2001:db8:113::1" should eventually succeed
    # With both members installed the kernel forwards through the primary.
    And ping from "z1" to "203.0.113.101" should eventually succeed
    And ping from "z1" to "2001:db8:113::101" should eventually succeed

  Scenario: The route stays installed while its backup is down
    Given the test topology exists
    When I make namespace "g2" interface "eth0" down
    Then kernel route "203.0.113.0/24" in namespace "z1" should eventually not contain "via 198.51.100.1"
    And kernel route "2001:db8:113::/48" in namespace "z1" should eventually not contain "via 2001:db8:b::1"
    And show command "show ip route" in namespace "z1" should eventually not contain "*?"
    And show command "show ipv6 route" in namespace "z1" should eventually not contain "*?"
    # The primary is still in the kernel, and still shown as installed.
    And kernel route "203.0.113.0/24" in namespace "z1" should eventually contain "via 192.0.2.1 dev wan0"
    And kernel route "2001:db8:113::/48" in namespace "z1" should eventually contain "via 2001:db8:a::1 dev wan0"
    And show command "show ip route" in namespace "z1" should eventually contain "*> 203.0.113.0/24 [1/0] via 192.0.2.1, wan0"
    And show command "show ipv6 route" in namespace "z1" should eventually contain "*> 2001:db8:113::/48 [1/0] via 2001:db8:a::1, wan0"
    When I make namespace "g2" interface "eth0" up
    Then kernel route "203.0.113.0/24" in namespace "z1" should eventually contain "via 198.51.100.1 dev wan1 proto zebra metric 10"
    And kernel route "2001:db8:113::/48" in namespace "z1" should eventually contain "via 2001:db8:b::1 dev wan1 proto zebra metric 10 onlink"
    And show command "show ip route" in namespace "z1" should eventually contain "*?"
    And show command "show ipv6 route" in namespace "z1" should eventually contain "*?"

  Scenario: The backup carries the route while the primary's link is down
    Given the test topology exists
    When I make namespace "g1" interface "eth0" down
    Then kernel route "203.0.113.0/24" in namespace "z1" should eventually not contain "via 192.0.2.1"
    And kernel route "2001:db8:113::/48" in namespace "z1" should eventually not contain "via 2001:db8:a::1"
    And kernel route "203.0.113.0/24" in namespace "z1" should eventually contain "via 198.51.100.1 dev wan1 proto zebra metric 10"
    And kernel route "2001:db8:113::/48" in namespace "z1" should eventually contain "via 2001:db8:b::1 dev wan1 proto zebra metric 10 onlink"
    # Selected, the primary no longer in the FIB, the backup still there.
    And show command "show ip route" in namespace "z1" should eventually contain " > 203.0.113.0/24 [1/0] via 192.0.2.1, wan0"
    And show command "show ip route" in namespace "z1" should eventually contain "*?"
    And show command "show ipv6 route" in namespace "z1" should eventually contain " > 2001:db8:113::/48 [1/0] via 2001:db8:a::1, wan0"
    And show command "show ipv6 route" in namespace "z1" should eventually contain "*?"
    And ping from "z1" to "203.0.113.1" should eventually succeed
    And ping from "z1" to "2001:db8:113::1" should eventually succeed
    When I make namespace "g1" interface "eth0" up
    Then kernel route "203.0.113.0/24" in namespace "z1" should eventually contain "via 192.0.2.1 dev wan0"
    And kernel route "2001:db8:113::/48" in namespace "z1" should eventually contain "via 2001:db8:a::1 dev wan0 proto zebra metric 1 onlink"
    And show command "show ip route" in namespace "z1" should eventually contain "*> 203.0.113.0/24 [1/0] via 192.0.2.1, wan0"
    And show command "show ipv6 route" in namespace "z1" should eventually contain "*> 2001:db8:113::/48 [1/0] via 2001:db8:a::1, wan0"
    # Back, the primary takes the traffic again.
    And ping from "z1" to "203.0.113.101" should eventually succeed
    And ping from "z1" to "2001:db8:113::101" should eventually succeed

  Scenario: A member whose gateway stops resolving leaves the kernel
    Given the test topology exists
    # wan0 loses its addresses but stays up: the kernel would go on
    # forwarding through the primary, whose nexthop object is still there.
    When I apply config "z1-no-wan0-address.yaml" to namespace "z1"
    Then kernel route "203.0.113.0/24" in namespace "z1" should eventually not contain "via 192.0.2.1"
    And kernel route "2001:db8:113::/48" in namespace "z1" should eventually not contain "via 2001:db8:a::1"
    And kernel route "203.0.113.0/24" in namespace "z1" should eventually contain "via 198.51.100.1 dev wan1 proto zebra metric 10"
    And kernel route "2001:db8:113::/48" in namespace "z1" should eventually contain "via 2001:db8:b::1 dev wan1 proto zebra metric 10 onlink"
    And show command "show ip route" in namespace "z1" should eventually contain " > 203.0.113.0/24 [1/0] via 192.0.2.1"
    And show command "show ip route" in namespace "z1" should eventually contain "*?"
    And ping from "z1" to "203.0.113.1" should eventually succeed
    And ping from "z1" to "2001:db8:113::1" should eventually succeed
    When I apply config "z1.yaml" to namespace "z1"
    Then kernel route "203.0.113.0/24" in namespace "z1" should eventually contain "via 192.0.2.1 dev wan0"
    And kernel route "2001:db8:113::/48" in namespace "z1" should eventually contain "via 2001:db8:a::1 dev wan0 proto zebra metric 1 onlink"
    And kernel route "203.0.113.0/24" in namespace "z1" should eventually contain "via 198.51.100.1 dev wan1 proto zebra metric 10"
    And show command "show ip route" in namespace "z1" should eventually contain "*> 203.0.113.0/24 [1/0] via 192.0.2.1, wan0"
    And show command "show ipv6 route" in namespace "z1" should eventually contain "*> 2001:db8:113::/48 [1/0] via 2001:db8:a::1, wan0"
    And ping from "z1" to "203.0.113.101" should eventually succeed
    And ping from "z1" to "2001:db8:113::101" should eventually succeed

  Scenario: A backup that is unreachable when the route is committed
    Given the test topology exists
    When I apply config "z1-no-static.yaml" to namespace "z1"
    Then kernel route "203.0.113.0/24" in namespace "z1" should eventually be gone
    And kernel route "2001:db8:113::/48" in namespace "z1" should eventually be gone
    When I make namespace "g2" interface "eth0" down
    Then kernel route "198.51.100.0/24" in namespace "z1" should eventually contain "linkdown"
    When I wait 2 seconds
    And I apply config "z1.yaml" to namespace "z1"
    Then kernel route "203.0.113.0/24" in namespace "z1" should eventually contain "via 192.0.2.1 dev wan0"
    And kernel route "2001:db8:113::/48" in namespace "z1" should eventually contain "via 2001:db8:a::1 dev wan0 proto zebra metric 1 onlink"
    And show command "show ip route" in namespace "z1" should eventually contain "*> 203.0.113.0/24 [1/0] via 192.0.2.1, wan0"
    And show command "show ipv6 route" in namespace "z1" should eventually contain "*> 2001:db8:113::/48 [1/0] via 2001:db8:a::1, wan0"
    And show command "show ip route" in namespace "z1" should not contain "*?"
    And kernel route "203.0.113.0/24" in namespace "z1" should eventually not contain "via 198.51.100.1"
    When I make namespace "g2" interface "eth0" up
    Then kernel route "203.0.113.0/24" in namespace "z1" should eventually contain "via 198.51.100.1 dev wan1 proto zebra metric 10"
    And kernel route "2001:db8:113::/48" in namespace "z1" should eventually contain "via 2001:db8:b::1 dev wan1 proto zebra metric 10 onlink"
    And show command "show ip route" in namespace "z1" should eventually contain "*?"
    And show command "show ipv6 route" in namespace "z1" should eventually contain "*?"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete namespace "g1"
    And I delete namespace "g2"
    Then the test environment should be clean
