@serial
@bgp_shard_lu
Feature: BGP IPv4 Labeled-Unicast (SAFI 4) withdraw/peer-down through a sharded daemon

  Companion to @bgp_shard_v6 for the SAFI-4 (labeled-unicast) Loc-RIB.
  Like v6-unicast, LU has no Adj-RIB-Out, so `route_labelv4_withdraw` must
  drop a no-op withdraw (one that removed nothing) before re-advertising —
  otherwise two speakers that both lack the prefix bounce MP_UNREACH
  forever, the same ping-pong fixed for v6-unicast. z2 runs with 4 shards
  (LU runs in-process at every N; the shards exercise the exact daemon
  configuration that first surfaced the v6 withdraw storm).

  A two-node z1—z2 topology is enough: z1 originates two LU prefixes after
  the session is Established (z2 ingests them live), and the withdraw of
  one of them floods back to z1 (the source), which is where the ping-pong
  starts. The withdraw and a peer-down (z1 killed) must each remove exactly
  the right routes from z2's LU Loc-RIB.

  Test Topology:
  ```
  z1 (AS65001) ── z2 (AS65002, 4 shards)
  192.168.0.1/24   192.168.0.2/24
  ```
  Both on bridge br0. z2's LU Loc-RIB is read directly (LU is in-process,
  so the N>1 pooled-`show` gap does not apply here).

  Scenario: Setup session with z2 sharded, before any routes exist
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2" with 4 shards
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: z1 originates LU routes; the sharded z2 ingests them
    Given the test topology exists
    When I apply config "z1-routes.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show ip bgp labeled-unicast" in namespace "z2" should contain "10.10.10.1/32"
    And show command "show ip bgp labeled-unicast" in namespace "z2" should contain "10.10.10.2/32"

  Scenario: z1 withdraws one LU route; the sharded withdraw drops only it
    Given the test topology exists
    # z1 keeps 10.10.10.2/32 but drops 10.10.10.1/32, so z1 withdraws .1.
    # z2 floods the withdraw back to z1 (the source); without the no-op
    # guard z1 re-floods it and the two storm MP_UNREACH. .2 staying is the
    # positive control, so the negative assertion is not vacuous.
    When I apply config "z1-withdraw1.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show ip bgp labeled-unicast" in namespace "z2" should not contain "10.10.10.1/32"
    And show command "show ip bgp labeled-unicast" in namespace "z2" should contain "10.10.10.2/32"

  Scenario: z1's session drops; sharded peer-down sweeps its LU routes
    Given the test topology exists
    # z2 still holds .2 from the previous scenario (positive control). Kill
    # z1 — z2's route_clean must withdraw 10.10.10.2/32 from its LU Loc-RIB.
    Then show command "show ip bgp labeled-unicast" in namespace "z2" should contain "10.10.10.2/32"
    When I stop zebra-rs in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should not be "Established"
    And show command "show ip bgp labeled-unicast" in namespace "z2" should not contain "10.10.10.2/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
