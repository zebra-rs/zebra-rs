@serial
@dhcp_client_dual_wan
Feature: Two DHCP uplinks: backup by distance, ECMP at equal distance

  Each DHCP interface's lease gives a default route at that interface's
  `dhcp-options default-route-distance` (default 210). The DHCP client
  hands the RIB the routes of the lowest distance among the uplinks whose
  link is up (docs/design/dhcp-client.md D6):

  - different distances: the lower one carries the traffic, and the other
    takes over when the first one's link goes down or its lease ends;
  - the same distance: one ECMP route over both, what VyOS gets from FRR
    for two DHCP uplinks left at the default.

  Topology: s1 and s2 are two ISPs, each a dnsmasq that is its lease's
  router, each with 198.51.100.1 on its loopback: an address r1 reaches
  through whichever uplink its default route uses.

      s1 srv0 192.0.2.1/24   ──── wan0 ┐
      lo 198.51.100.1/32                r1 (zebra-rs)
      s2 srv0 203.0.113.1/24 ──── wan1 ┘   wan1: default-route-distance 220
      lo 198.51.100.1/32

  Config files:
  - r1.yaml: `address dhcp` on wan0 and wan1, wan1 at distance 220.

  Scenario: Setup two servers and a router with two DHCP uplinks
    Given a clean test environment
    When I create namespace "s1"
    And I create namespace "s2"
    And I create namespace "r1"
    And I connect namespace "s1" interface "srv0" to namespace "r1" interface "wan0"
    And I connect namespace "s2" interface "srv0" to namespace "r1" interface "wan1"
    And I execute "tests/scripts/dhcp_server.sh dhcp_client_dual_wan_s1 start srv0 192.0.2.1/24 192.0.2.100 192.0.2.150 120" in namespace "s1"
    And I execute "tests/scripts/dhcp_server.sh dhcp_client_dual_wan_s2 start srv0 203.0.113.1/24 203.0.113.100 203.0.113.150 120" in namespace "s2"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then show command "show dhcp client leases interface wan0" in namespace "r1" should eventually contain "State:        bound"
    And show command "show dhcp client leases interface wan1" in namespace "r1" should eventually contain "State:        bound"

  Scenario: The lower distance carries the traffic
    Given the test topology exists
    Then show command "show ip route" in namespace "r1" should eventually contain "0.0.0.0/0 [210/0] via 192.0.2.1, wan0"
    And show command "show ip route" in namespace "r1" should not contain "via 203.0.113.1, wan1"
    And show command "show dhcp client leases interface wan1" in namespace "r1" should contain "0.0.0.0/0 via 203.0.113.1 [220]"
    And ping from "r1" to "198.51.100.1" should eventually succeed

  Scenario: The backup takes over while the primary's link is down
    Given the test topology exists
    When I make namespace "s1" interface "srv0" down
    Then show command "show ip route" in namespace "r1" should eventually contain "0.0.0.0/0 [220/0] via 203.0.113.1, wan1"
    And show command "show ip route" in namespace "r1" should not contain "via 192.0.2.1, wan0"
    And show command "show dhcp client leases interface wan0" in namespace "r1" should contain "Address:      192.0.2.1"
    And ping from "r1" to "198.51.100.1" should eventually succeed
    When I make namespace "s1" interface "srv0" up
    Then show command "show ip route" in namespace "r1" should eventually contain "0.0.0.0/0 [210/0] via 192.0.2.1, wan0"
    And show command "show ip route" in namespace "r1" should eventually not contain "via 203.0.113.1, wan1"
    And ping from "r1" to "198.51.100.1" should eventually succeed

  Scenario: The backup takes over when the primary's lease is released
    Given the test topology exists
    Then show command "release dhcp interface wan0" in namespace "r1" should contain "Released the DHCP lease on wan0"
    And show command "show ip route" in namespace "r1" should eventually contain "0.0.0.0/0 [220/0] via 203.0.113.1, wan1"
    And show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show ip route" in namespace "r1" should eventually contain "0.0.0.0/0 [210/0] via 192.0.2.1, wan0"

  Scenario: Equal distances share the traffic
    Given the test topology exists
    When I apply command "delete interface wan1 ipv4 dhcp-options default-route-distance" in namespace "r1"
    Then show command "show ip route" in namespace "r1" should eventually contain "via 203.0.113.1, wan1, weight 1"
    And show command "show ip route" in namespace "r1" should contain "0.0.0.0/0 [210/0] via 192.0.2.1, wan0, weight 1"
    And ping from "r1" to "198.51.100.1" should eventually succeed
    When I make namespace "s2" interface "srv0" down
    Then show command "show ip route" in namespace "r1" should eventually not contain "via 203.0.113.1, wan1"
    And show command "show ip route" in namespace "r1" should contain "0.0.0.0/0 [210/0] via 192.0.2.1, wan0"
    When I make namespace "s2" interface "srv0" up
    Then show command "show ip route" in namespace "r1" should eventually contain "via 203.0.113.1, wan1, weight 1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_server.sh dhcp_client_dual_wan_s1 stop" in namespace "s1"
    And I execute "tests/scripts/dhcp_server.sh dhcp_client_dual_wan_s2 stop" in namespace "s2"
    And I delete namespace "r1"
    And I delete namespace "s1"
    And I delete namespace "s2"
    Then the test environment should be clean
