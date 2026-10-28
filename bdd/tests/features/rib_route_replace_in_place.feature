@serial
@rib_route_replace_in_place
Feature: RIB replaces a route in the kernel without deleting it first

  When a protocol re-adds a route the RIB already holds, or another route
  outranks the installed one, the RIB used to delete the installed route
  from the kernel and then add the new one, so the prefix had no route in
  between. That happened on every change of the route, even one that
  leaves forwarding as it was, such as a neighbor sending the same route
  again.

  Now the new route goes in first. Its install replaces the kernel route
  at the same priority in place (NLM_F_REPLACE), and only the old route's
  routes at other priorities are deleted after it. FPM and cradle key a
  route by prefix, so the new route's tee overwrites the old one there.

  z2 is the device under test. It learns 10.70.1.0/24 from z1, then is
  sent it again unchanged, sees it change next hop to z3, and sees it
  outranked by a static route and handed back, all at kernel priority 0. A recording of
  z2's kernel route events must show no deletion of the prefix through
  all of that, while a real withdraw at the end is recorded as one.

  Test Topology:
  ```
  z1 (AS65001) ── z2 (AS65002) ── z3 (AS65003)
   10.0.0.1/24    10.0.0.2/24     10.0.0.3/24
  ```
  All three on bridge br0; z1 and z3 originate 10.70.1.0/24.

  Scenario: z2 installs 10.70.1.0/24 from z1
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "10.0.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "10.0.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "10.0.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z2" to "10.0.0.1" should eventually be "Established"
    And command "ip route show 10.70.1.0/24" in namespace "z2" should eventually contain "via 10.0.0.1"
    When I spawn "python3 tests/scripts/route_monitor.py record logs/rib_route_replace_in_place_z2.routes.log 120" in namespace "z2"

  Scenario: the same route sent again
    Given the test topology exists
    # z2 reinstalls the unchanged best path, as in #2599. (A route-map
    # attached in the same commit that defines it is a worse trigger: until
    # it resolves it denies, so z1 really withdraws the route first.)
    When I run "clear bgp ipv4 neighbor 10.0.0.2 soft out" in namespace "z1"
    And I wait 3 seconds for BGP to operate

  Scenario: a new next hop
    Given the test topology exists
    # z3's path arrives second, so z1's stays best until z1 withdraws.
    When I apply config "z3.yaml" to namespace "z3"
    Then BGP session in "z2" to "10.0.0.3" should eventually be "Established"
    And show command "show bgp ipv4 10.70.1.0/24" in namespace "z2" should eventually contain "10.0.0.3"
    When I apply config "z1-withdraw.yaml" to namespace "z1"
    Then command "ip route show 10.70.1.0/24" in namespace "z2" should eventually contain "via 10.0.0.3"

  Scenario: a static route outranks the BGP route, then hands it back
    Given the test topology exists
    When I apply config "z2-static.yaml" to namespace "z2"
    Then command "ip route show 10.70.1.0/24" in namespace "z2" should eventually contain "via 10.0.0.9"
    When I apply config "z2.yaml" to namespace "z2"
    Then command "ip route show 10.70.1.0/24" in namespace "z2" should eventually contain "via 10.0.0.3"

  Scenario: none of the changes deleted the prefix from the kernel
    Given the test topology exists
    # The recording saw the next-hop change and the static route (which
    # zebra-rs installs as proto zebra), so the check for a deletion
    # covers them.
    Then command "python3 tests/scripts/route_monitor.py show logs/rib_route_replace_in_place_z2.routes.log 10.70.1.0/24" in namespace "z2" should eventually contain "via 10.0.0.3"
    And command "python3 tests/scripts/route_monitor.py show logs/rib_route_replace_in_place_z2.routes.log 10.70.1.0/24" in namespace "z2" should eventually contain "via 10.0.0.9"
    And command "python3 tests/scripts/route_monitor.py show logs/rib_route_replace_in_place_z2.routes.log 10.70.1.0/24" in namespace "z2" should not contain "Deleted"

  Scenario: a withdraw still deletes the route, and the recording shows it
    Given the test topology exists
    When I apply config "z3-withdraw.yaml" to namespace "z3"
    Then command "ip route show 10.70.1.0/24" in namespace "z2" should eventually not contain "10.70.1.0/24"
    And command "python3 tests/scripts/route_monitor.py show logs/rib_route_replace_in_place_z2.routes.log 10.70.1.0/24" in namespace "z2" should eventually contain "Deleted"

  Scenario: Teardown topology
    Given the test topology exists
    When I execute "python3 tests/scripts/route_monitor.py stop logs/rib_route_replace_in_place_z2.routes.log" in namespace "z2"
    And I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
