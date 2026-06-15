@serial
@bgp_shard_v4_sync
Feature: BGP IPv4-unicast read paths at N>1 (show / session-up sync read the empty main shard)

  Regression test for a correctness gap in BGP RIB sharding. At
  ZEBRA_BGP_SHARDS>1, plain IPv4-unicast routes are dispatched to the
  worker-shard pool (RouteBatchV4) and live ONLY in the pool shards; the
  reduce (`reduce_bestpath_v4_nht_fib`) does FIB-install + advertise but
  never mirrors the best-path back into the synchronous `bgp.shard`. So
  every read path that consults `bgp.shard.v4` is empty at N>1:

    * `show bgp ipv4` — the operator can't see the v4 Loc-RIB;
    * `route_sync_ipv4` — a peer that establishes AFTER routes exist gets
      only the End-of-RIB marker (no routes).

  Forwarding itself is unaffected: the event-driven advertise runs off the
  best-path delta, not `bgp.shard`. This is IPv4-unicast-specific (the only
  pooled family); v6 / VPNv4 / VPNv6 / labeled-unicast are sync-ingested,
  so their `bgp.shard` tables stay populated and read correctly at N>1.

  z2 is the sharded device under test (4 shards) and the transit between
  z1 (origin) and two downstream peers:
    * z3 establishes BEFORE the routes exist → learns them via the
      EVENT-DRIVEN advertise (off the delta) — the positive control, PASSES.
    * z4 establishes AFTER the routes exist → can only learn them via z2's
      session-up `route_sync_ipv4` — the broken path, FAILS at N>1.

  EXPECTED STATE: scenario "z4 ... sync" and the z2 `show` assertion
  currently FAIL at N>1 (the bug); both PASS once the B.4 read-path
  scatter-gather lands (see docs/design/bgp-rib-sharding-plan.md §12).

  Test Topology:
  ```
                         ┌── z3 (AS65003)  early peer  → event-driven (control)
  z1 (AS65001) ── z2 (AS65002, 4 shards) ──┤
   10.0.0.1/24    10.0.0.2/24              └── z4 (AS65004)  late peer   → sync (bug)
   origin         sharded transit
  ```
  All four on bridge br0. z1 originates 10.10.10.0/24 + 10.10.11.0/24.

  Scenario: z1, the sharded z2, and the early peer z3 come up (no routes yet)
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "10.0.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "10.0.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "10.0.0.3/24" on bridge "br0"
    And I create namespace "z4" with IP "10.0.0.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2" with 4 shards
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "10.0.0.1" should be "Established"
    And BGP session in "z2" to "10.0.0.3" should be "Established"

  Scenario: control — z1 originates while z3 is up; the event-driven advertise reaches z3
    Given the test topology exists
    # z3 was Established before the routes existed, so it learns them via
    # the event-driven advertise (which runs off the best-path delta, not
    # bgp.shard). This MUST pass at N>1 — it proves the sharded z2 ingests
    # and forwards correctly, so the z4 failure below is the read path, not
    # ingest/forwarding.
    When I apply config "z1-routes.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp ipv4" in namespace "z3" should contain "10.10.10.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.10.11.0/24"

  Scenario: bug — the late peer z4 gets nothing on sync, and z2 can't even show its own RIB
    Given the test topology exists
    # z4's daemon starts now — AFTER z2 already holds z1's routes — so z4 can
    # obtain them only via z2's `route_sync_ipv4` initial dump. And z2's own
    # `show bgp ipv4` reads the same `bgp.shard.v4`. Both read the empty main
    # shard at N>1, so these FAIL today (the bug) and PASS once fixed.
    When I start zebra-rs in namespace "z4"
    And I apply config "z4.yaml" to namespace "z4"
    And I wait 15 seconds for BGP to operate
    Then BGP session in "z2" to "10.0.0.4" should be "Established"
    And show command "show bgp ipv4" in namespace "z4" should contain "10.10.10.0/24"
    And show command "show bgp ipv4" in namespace "z4" should contain "10.10.11.0/24"
    And show command "show bgp ipv4" in namespace "z2" should contain "10.10.10.0/24"
    And show command "show bgp ipv4" in namespace "z2" should contain "10.10.11.0/24"

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
