@serial
@bgp_shard_sync_lu
Feature: BGP labeled-unicast (v4) session-up sync at N>1 (sync + withdraw reach a late peer)

  The labeled-unicast counterpart of @bgp_shard_v4_sync / @bgp_shard_sync_v6.
  At ZEBRA_BGP_SHARDS>1, labeled-unicast is sync-ingested to the main
  `bgp.shard` (not pooled), so `bgp.shard.v4lu` stays populated and the
  read paths work. The risk this pins is the Adj-RIB-Out one v6 exposed:
  `route_sync_labelv4` dumps the LU Loc-RIB to a newly-established peer and
  must register each prefix in `adj_out.v4lu`, otherwise the event-driven
  LU withdraw's `adj_out.v4lu` gate skips that peer and the route gets
  stuck. (route_sync_labelv6 carries the byte-identical fix.)

  z2 is the sharded device under test (4 shards) and transit between
  z1 (origin) and two downstream peers:
    * z3 establishes BEFORE the routes exist → event-driven (control);
    * z4 establishes AFTER the routes exist → session-up `route_sync_labelv4`.

  Test Topology:
  ```
                            ┌── z3 (AS65003)  early peer  → event-driven (control)
  z1 (AS65001) ── z2 (AS65002, 4 shards) ──┤
   192.168.0.1/24  192.168.0.2/24          └── z4 (AS65004)  late peer  → sync
   origin          sharded transit
  ```
  All four on bridge br0. z1 originates LU 10.10.10.1/32 + 10.10.10.2/32.

  Scenario: z1, the sharded z2, and the early peer z3 come up (no routes yet)
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.0.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2" with 4 shards
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z2" to "192.168.0.3" should be "Established"

  Scenario: control — z1 originates while z3 is up; the event-driven advertise reaches z3
    Given the test topology exists
    When I apply config "z1-routes.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp labeled-unicast" in namespace "z3" should contain "10.10.10.1/32"
    And show command "show bgp labeled-unicast" in namespace "z3" should contain "10.10.10.2/32"

  Scenario: the late peer z4 gets the routes on sync, and z2 can show its own RIB
    Given the test topology exists
    # z4's daemon starts now — AFTER z2 already holds z1's LU routes — so z4
    # can obtain them only via z2's `route_sync_labelv4` initial dump.
    When I start zebra-rs in namespace "z4"
    And I apply config "z4.yaml" to namespace "z4"
    And I wait 15 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.4" should be "Established"
    And show command "show bgp labeled-unicast" in namespace "z4" should contain "10.10.10.1/32"
    And show command "show bgp labeled-unicast" in namespace "z4" should contain "10.10.10.2/32"
    And show command "show bgp labeled-unicast" in namespace "z2" should contain "10.10.10.1/32"
    And show command "show bgp labeled-unicast" in namespace "z2" should contain "10.10.10.2/32"

  Scenario: z1 withdraws one route; the withdraw reaches the synced peer z4
    Given the test topology exists
    # z1 re-originates only 10.10.10.2/32 (dropping .1). The KEY assertion:
    # z4 — which learned .1 via the session-up sync — must lose it. Without
    # route_sync_labelv4 registering adj_out.v4lu, the withdraw's gate skips
    # z4 and .1 stays stuck (the bug this feature guards).
    When I apply config "z1-withdraw.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp labeled-unicast" in namespace "z2" should not contain "10.10.10.1/32"
    And show command "show bgp labeled-unicast" in namespace "z2" should contain "10.10.10.2/32"
    And show command "show bgp labeled-unicast" in namespace "z4" should not contain "10.10.10.1/32"
    And show command "show bgp labeled-unicast" in namespace "z4" should contain "10.10.10.2/32"

  Scenario: z1's session drops; the peer-down sweep clears its routes from z4
    Given the test topology exists
    # z4 still holds .2 (positive control). Stop z1 — z2's route_clean sweep
    # withdraws .2, which must also reach the synced peer z4.
    Then show command "show bgp labeled-unicast" in namespace "z4" should contain "10.10.10.2/32"
    When I stop zebra-rs in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should not be "Established"
    And show command "show bgp labeled-unicast" in namespace "z2" should not contain "10.10.10.2/32"
    And show command "show bgp labeled-unicast" in namespace "z4" should not contain "10.10.10.2/32"

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
