@serial
@bgp_shard_sync_labelv6
Feature: BGP labeled-unicast (v6) session-up sync at N>1 (sync + withdraw reach a late peer)

  The IPv6 labeled-unicast counterpart of @bgp_shard_sync_lu, exercising
  `route_sync_labelv6`. At ZEBRA_BGP_SHARDS>1 labeled-unicast is
  sync-ingested to the main `bgp.shard` (not pooled), so `bgp.shard.v6lu`
  stays populated and the read paths work. The risk this pins is the
  Adj-RIB-Out one v6/LU-v4 exposed: `route_sync_labelv6` dumps the LU-v6
  Loc-RIB to a newly-established peer and must register each prefix in
  `adj_out.v6lu`, otherwise the event-driven LU withdraw's gate skips that
  peer and the route gets stuck. (This is native LU-v6 over an IPv6
  session; the next-hop-self is the v6 session local address.)

  z2 is the sharded device under test (4 shards) and transit between
  z1 (origin) and two downstream peers:
    * z3 establishes BEFORE the routes exist → event-driven (control);
    * z4 establishes AFTER the routes exist → session-up `route_sync_labelv6`.

  `show bgp labeled-unicast` renders both the v4lu and v6lu Loc-RIBs, so
  the v6 LU prefixes appear there.

  Test Topology:
  ```
                            ┌── z3 (AS65003)  early peer  → event-driven (control)
  z1 (AS65001) ── z2 (AS65002, 4 shards) ──┤
   2001:db8::1/64  2001:db8::2/64          └── z4 (AS65004)  late peer  → sync
   origin          sharded transit
  ```
  All four on bridge br0. z1 originates LU-v6 2001:db8:a::1/128 + ::2/128.

  Scenario: z1, the sharded z2, and the early peer z3 come up (no routes yet)
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8::2/64" on bridge "br0"
    And I create namespace "z3" with IP "2001:db8::3/64" on bridge "br0"
    And I create namespace "z4" with IP "2001:db8::4/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2" with 4 shards
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "2001:db8::1" should be "Established"
    And BGP session in "z2" to "2001:db8::3" should be "Established"

  Scenario: control — z1 originates while z3 is up; the event-driven advertise reaches z3
    Given the test topology exists
    When I apply config "z1-routes.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp labeled-unicast" in namespace "z3" should contain "2001:db8:a::1/128"
    And show command "show bgp labeled-unicast" in namespace "z3" should contain "2001:db8:a::2/128"

  Scenario: the late peer z4 gets the routes on sync, and z2 can show its own RIB
    Given the test topology exists
    # z4's daemon starts now — AFTER z2 already holds z1's LU-v6 routes — so
    # z4 can obtain them only via z2's `route_sync_labelv6` initial dump.
    When I start zebra-rs in namespace "z4"
    And I apply config "z4.yaml" to namespace "z4"
    And I wait 15 seconds for BGP to operate
    Then BGP session in "z2" to "2001:db8::4" should be "Established"
    And show command "show bgp labeled-unicast" in namespace "z4" should contain "2001:db8:a::1/128"
    And show command "show bgp labeled-unicast" in namespace "z4" should contain "2001:db8:a::2/128"
    And show command "show bgp labeled-unicast" in namespace "z2" should contain "2001:db8:a::1/128"
    And show command "show bgp labeled-unicast" in namespace "z2" should contain "2001:db8:a::2/128"

  Scenario: z1 withdraws one route; the withdraw reaches the synced peer z4
    Given the test topology exists
    # z1 re-originates only ::2 (dropping ::1). The KEY assertion: z4 — which
    # learned ::1 via the session-up sync — must lose it. Without
    # route_sync_labelv6 registering adj_out.v6lu, the withdraw's gate skips
    # z4 and ::1 stays stuck (the bug this feature guards).
    When I apply config "z1-withdraw.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp labeled-unicast" in namespace "z2" should not contain "2001:db8:a::1/128"
    And show command "show bgp labeled-unicast" in namespace "z2" should contain "2001:db8:a::2/128"
    And show command "show bgp labeled-unicast" in namespace "z4" should not contain "2001:db8:a::1/128"
    And show command "show bgp labeled-unicast" in namespace "z4" should contain "2001:db8:a::2/128"

  Scenario: z1's session drops; the peer-down sweep clears its routes from z4
    Given the test topology exists
    # z4 still holds ::2 (positive control). Stop z1 — z2's route_clean sweep
    # withdraws ::2, which must also reach the synced peer z4.
    Then show command "show bgp labeled-unicast" in namespace "z4" should contain "2001:db8:a::2/128"
    When I stop zebra-rs in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "2001:db8::1" should not be "Established"
    And show command "show bgp labeled-unicast" in namespace "z2" should not contain "2001:db8:a::2/128"
    And show command "show bgp labeled-unicast" in namespace "z4" should not contain "2001:db8:a::2/128"

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
