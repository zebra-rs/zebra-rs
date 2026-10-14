@serial
@bgp_fib_pending_sharded_dump
Feature: A neighbor that comes up waits for the forwarding plane under RIB sharding
  As a network operator running suppress-fib-pending with RIB sharding
  (router bgp sharding rib-sharding > 1)
  I want a neighbor that comes up while a prefix awaits the forwarding
  plane's ack to learn that prefix only once the ack, or the deadline,
  releases it
  So no neighbor is told about a route we may not forward yet.

  With suppress-fib-pending a prefix's advertisement waits for the
  forwarding plane to confirm the install. The session-up dumps on main
  skip a held prefix and leave it to the release; with RIB sharding the
  IPv4-unicast dump runs in the shard pool instead, which had no such gate,
  so a neighbor that came up learned the held prefix at once (review
  finding #30). Nothing here acknowledges installs (no FPM), so every hold
  runs to its 30-second deadline: that window is the test. IPv4 only — the
  pool serves plain IPv4 unicast; the IPv6 session-up dump runs on main.

  Test Topology:
  ```
  z2 (AS65002) ── z1 (AS65001) ── z3 (AS65003)
   origin          DUT:            late peer
                   rib-sharding 2,
                   suppress-fib-pending
  ```
  All three on bridge br0 10.0.30.0/24. z2 originates 10.30.10.0/24 once
  z1 is up with it; z3 comes up while z1 still holds it.

  Config files:
  - z1.yaml: DUT — rib-sharding 2, suppress-fib-pending; eBGP to z2, z3.
  - z2-base.yaml: eBGP to z1, no routes. z2-route.yaml: the route.
  - z3.yaml: eBGP to z1.

  Scenario: Setup; z1 shards its RIB and z2 establishes
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "10.0.30.1/24" on bridge "br0"
    And I create namespace "z2" with IP "10.0.30.2/24" on bridge "br0"
    And I create namespace "z3" with IP "10.0.30.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2-base.yaml" to namespace "z2"
    Then BGP session in "z1" to "10.0.30.2" should eventually be "Established"
    And the zebra-rs log in namespace "z1" should contain "BGP RIB sharding: 2 shards (from config)"
    And show command "show bgp summary" in namespace "z1" should contain "FIB-pending suppression: enabled, 0 held"

  Scenario: z1 holds z2's route for the forwarding plane
    Given the test topology exists
    When I apply config "z2-route.yaml" to namespace "z2"
    Then show command "show bgp ipv4" in namespace "z1" should eventually contain "10.30.10.0/24"
    And show command "show bgp summary" in namespace "z1" should contain "FIB-pending suppression: enabled, 1 held"

  Scenario: The late peer's session-up dump holds the route back
    Given the test topology exists
    When I start zebra-rs in namespace "z3"
    And I apply config "z3.yaml" to namespace "z3"
    Then BGP session in "z1" to "10.0.30.3" should eventually be "Established"
    And I wait 3 seconds
    # The dump ran at Established, while z1 still held the route.
    And show command "show bgp summary" in namespace "z1" should contain "FIB-pending suppression: enabled, 1 held"
    # Pre-fix the pool's dump sent it at once.
    And show command "show bgp ipv4" in namespace "z3" should not contain "10.30.10.0/24"

  Scenario: The deadline releases the route to the late peer
    Given the test topology exists
    Then show command "show bgp summary" in namespace "z1" should contain "FIB-pending suppression: enabled, 0 held, 1 released by timeout" within 60 seconds
    And show command "show bgp ipv4" in namespace "z3" should eventually contain "10.30.10.0/24"
    And BGP session in "z1" to "10.0.30.3" should be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
