@serial
@bgp_shard_config_knob
Feature: BGP RIB sharding configured via the router bgp shards YANG knob

  Validates the C.4 shipping form of RIB sharding: the shard count comes
  from config (`router bgp shards <1-64>`, zebra-bgp-sharding.yang) instead
  of the `ZEBRA_BGP_SHARDS` environment variable. The sharded device z2 is
  started with the PLAIN `start zebra-rs` step — no env var — and gets its
  shard count purely from `shards: 4` in its applied config.

  Sharding is behavior-transparent (the same correct result at N=1 and
  N>1), so a correctness matrix alone cannot prove the knob actually
  activated N=4 — it would pass even if the daemon silently fell back to
  N=1. The decisive assertion is therefore the startup log line
  `BGP RIB sharding: 4 shards (from config)`, emitted by `init_shard_count`
  when `spawn_bgp` reads the leaf — which is true only if the knob resolved
  to 4 from config. The route-propagation scenario then confirms the
  config-sharded daemon ingests and forwards correctly end to end.

  The env-driven N>1 read-path matrix (mirror, late-peer sync,
  received-routes gather, withdraw, peer-down) is covered by the
  bgp_shard_v4_sync feature; this one focuses on the config-knob plumbing.

  Test Topology:
  ```
  z1 (AS65001) ── z2 (AS65002) ── z3 (AS65003)
   10.0.0.1/24    10.0.0.2/24     10.0.0.3/24
   origin         shards: 4       peer
                  (from config)
  ```
  All three on bridge br0. z1 originates 10.10.10.0/24 + 10.10.11.0/24.

  Scenario: z2 is sharded by config (not env) and the speakers establish
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "10.0.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "10.0.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "10.0.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    # The decisive proof: z2 read `shards: 4` from its config (no env var was
    # set) and spawned the pool with 4 shards. This line is emitted only when
    # the knob resolves to 4 from config — N=1 would log "1 shard".
    Then the zebra-rs log in namespace "z2" should contain "BGP RIB sharding: 4 shards (from config)"
    And BGP session in "z2" to "10.0.0.1" should be "Established"
    And BGP session in "z2" to "10.0.0.3" should be "Established"

  Scenario: routes propagate through the config-sharded z2
    Given the test topology exists
    # z1 originates; the config-sharded z2 must ingest (pool), best-path, and
    # advertise to z3 — proving the knob's pool is functional, not just
    # spawned. z2's own `show bgp ipv4` reads the N>1 read-replica mirror.
    When I apply config "z1-routes.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp ipv4" in namespace "z2" should contain "10.10.10.0/24"
    And show command "show bgp ipv4" in namespace "z2" should contain "10.10.11.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.10.10.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.10.11.0/24"

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
