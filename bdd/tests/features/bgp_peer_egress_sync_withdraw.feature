@serial
@bgp_peer_egress_sync_withdraw
Feature: A route a late peer learned at session-up is withdrawn through the per-peer egress task
  As a network operator running the per-peer egress task
  (router bgp sharding peer-sharding true)
  I want a neighbor that came up after a route was learned to lose that
  route when it is withdrawn
  So no neighbor keeps forwarding to us on a route we no longer have.

  A neighbor that comes up is sent the routes already held (the session-up
  dump). With the per-peer egress task and no RIB sharding (N=1), the dump
  was never recorded in the task's Adj-RIB-Out; the task sends a withdraw
  only for a route it recorded, so every route the neighbor learned from
  the dump stayed with it, and `advertised-routes` did not list them. The
  task serves IPv4 unicast only, so there is no IPv6 twin.

  Test Topology:
  ```
                                ┌── z3 (AS65003)  early peer
  z1 (AS65001) ── z2 (AS65002) ─┤
   origin         peer-sharding └── z4 (AS65004)  late peer
                  true (N=1)
  ```
  All four on bridge br0 10.0.25.0/24. z1 originates 10.25.10.0/24 and
  10.25.11.0/24 after z3 is up (z3 learns them event-driven, the control)
  and before z4 is (z4 learns them from the dump).

  Config files:
  - z1-base.yaml: eBGP to z2, no routes. z1-routes.yaml: the two routes.
  - z2.yaml: DUT — peer-sharding true, rib-sharding unset; eBGP to z1, z3, z4.
  - z3.yaml, z4.yaml: eBGP to z2.

  Scenario: Setup; z2 runs the per-peer egress task and z3 establishes
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "10.0.25.1/24" on bridge "br0"
    And I create namespace "z2" with IP "10.0.25.2/24" on bridge "br0"
    And I create namespace "z3" with IP "10.0.25.3/24" on bridge "br0"
    And I create namespace "z4" with IP "10.0.25.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    Then BGP session in "z2" to "10.0.25.1" should eventually be "Established"
    And BGP session in "z2" to "10.0.25.3" should eventually be "Established"
    And the zebra-rs log in namespace "z2" should contain "BGP per-peer egress task: enabled (from config)"

  Scenario: z1's routes reach the early peer event-driven
    Given the test topology exists
    When I apply config "z1-routes.yaml" to namespace "z1"
    Then show command "show bgp ipv4" in namespace "z3" should eventually contain "10.25.10.0/24"
    And show command "show bgp ipv4" in namespace "z3" should eventually contain "10.25.11.0/24"

  Scenario: The late peer learns the routes from the session-up dump
    Given the test topology exists
    When I start zebra-rs in namespace "z4"
    And I apply config "z4.yaml" to namespace "z4"
    Then BGP session in "z2" to "10.0.25.4" should eventually be "Established"
    And show command "show bgp ipv4" in namespace "z4" should eventually contain "10.25.10.0/24"
    And show command "show bgp ipv4" in namespace "z4" should eventually contain "10.25.11.0/24"
    # Pre-fix the task's Adj-RIB-Out held none of the dumped routes.
    And show command "show bgp neighbor 10.0.25.4 advertised-routes" in namespace "z2" should eventually contain "10.25.10.0/24"
    And show command "show bgp neighbor 10.0.25.4 advertised-routes" in namespace "z2" should contain "10.25.11.0/24"

  Scenario: z1 withdraws the routes; both peers lose them
    Given the test topology exists
    When I apply config "z1-base.yaml" to namespace "z1"
    # Control: the early peer learned them event-driven.
    Then show command "show bgp ipv4" in namespace "z3" should eventually not contain "10.25.10.0/24"
    And show command "show bgp ipv4" in namespace "z3" should eventually not contain "10.25.11.0/24"
    # Pre-fix the late peer kept every route it learned from the dump.
    And show command "show bgp ipv4" in namespace "z4" should eventually not contain "10.25.10.0/24"
    And show command "show bgp ipv4" in namespace "z4" should eventually not contain "10.25.11.0/24"
    And BGP session in "z2" to "10.0.25.4" should be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "z4"
    And I delete bridge "br0"
    Then the test environment should be clean
