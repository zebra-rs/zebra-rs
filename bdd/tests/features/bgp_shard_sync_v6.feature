@serial
@bgp_shard_sync_v6
Feature: BGP IPv6-unicast read paths at N>1 (sync / show stay correct — v6 is not pooled)

  The IPv6 counterpart of @bgp_shard_v4_sync, asserting the *absence* of
  the read-path bug for v6. At ZEBRA_BGP_SHARDS>1 only plain v4-unicast is
  dispatched to the worker pool; IPv6-unicast is sync-ingested straight to
  the main `bgp.shard` (no `RouteBatchV6`). So `bgp.shard.v6` stays
  populated at N>1, and the synchronous main-task read paths —
  `route_sync_ipv6` (session-up dump) and `show bgp ipv6` — see the routes
  with no mirror needed. This feature pins that: a late-establishing v6
  peer must still get the full table on sync, and the sharded node must
  show its own v6 RIB. (v4 needed `BgpShard::mirror_v4` for this; v6 does
  not, and this guards against v6 ever regressing into the same hole.)

  z2 is the sharded device under test (4 shards) and the transit between
  z1 (origin) and two downstream peers:
    * z3 establishes BEFORE the routes exist → event-driven advertise
      (positive control);
    * z4 establishes AFTER the routes exist → session-up `route_sync_ipv6`.

  Test Topology:
  ```
                            ┌── z3 (AS65003)  early peer  → event-driven (control)
  z1 (AS65001) ── z2 (AS65002, 4 shards) ──┤
   2001:db8::1/64  2001:db8::2/64          └── z4 (AS65004)  late peer   → sync
   origin          sharded transit
  ```
  All four on bridge br0. z1 originates 2001:db8:a::1/128 + 2001:db8:a::2/128.

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
    Then show command "show bgp ipv6" in namespace "z3" should contain "2001:db8:a::1/128"
    And show command "show bgp ipv6" in namespace "z3" should contain "2001:db8:a::2/128"

  Scenario: the late peer z4 gets the routes on sync, and z2 can show its own RIB
    Given the test topology exists
    # z4's daemon starts now — AFTER z2 already holds z1's routes — so z4 can
    # obtain them only via z2's `route_sync_ipv6` initial dump. v6 is
    # sync-ingested, so `bgp.shard.v6` is populated and both read paths work.
    When I start zebra-rs in namespace "z4"
    And I apply config "z4.yaml" to namespace "z4"
    And I wait 15 seconds for BGP to operate
    Then BGP session in "z2" to "2001:db8::4" should be "Established"
    And show command "show bgp ipv6" in namespace "z4" should contain "2001:db8:a::1/128"
    And show command "show bgp ipv6" in namespace "z4" should contain "2001:db8:a::2/128"
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:a::1/128"
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:a::2/128"

  Scenario: z1 withdraws one route; z2's sync shard drops it
    Given the test topology exists
    # z1 re-originates only 2001:db8:a::2/128 (dropping ::1). z2 ingests the
    # withdraw on its sync shard, so `show bgp ipv6` no longer lists ::1; ::2
    # staying is the positive control, z4 losing ::1 confirms propagation.
    When I apply config "z1-withdraw.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp ipv6" in namespace "z2" should not contain "2001:db8:a::1/128"
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:a::2/128"
    And show command "show bgp ipv6" in namespace "z4" should not contain "2001:db8:a::1/128"
    And show command "show bgp ipv6" in namespace "z4" should contain "2001:db8:a::2/128"

  Scenario: z1's session drops; the peer-down sweep clears its routes
    Given the test topology exists
    # z2 still holds ::2 (positive control). Stop z1 — z2's route_clean sweeps
    # z1's v6 slice so `show bgp ipv6` no longer lists it.
    Then show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:a::2/128"
    When I stop zebra-rs in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "2001:db8::1" should not be "Established"
    And show command "show bgp ipv6" in namespace "z2" should not contain "2001:db8:a::2/128"
    And show command "show bgp ipv6" in namespace "z4" should not contain "2001:db8:a::2/128"

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
