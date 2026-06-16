@serial
@bgp_peer_task_config_knob
Feature: BGP per-peer egress task configured via the router bgp peer-task knob

  Validates the shipping form of the per-peer egress task (PET): the egress
  model comes from config (router bgp peer-task true, zebra-bgp-sharding.yang)
  instead of the ZEBRA_BGP_PEER_TASK environment variable. The device z2 is
  started with the PLAIN start step — no env vars — and reads BOTH its shard
  count (shards: 4) and its egress model (peer-task: true) from config.

  PET runs the v4-unicast egress through a per-peer task (the GoBGP per-peer
  model) instead of the main-task update-groups, and is exercised together
  with sharding, so z2 sets both knobs. Like sharding, the egress model is
  behavior-transparent, so the decisive proof that the knob took effect is
  the startup log line BGP per-peer egress task: enabled (from config),
  emitted by init_peer_task when spawn_bgp reads the leaf. The
  route-propagation scenario then confirms the config-driven PET egress
  ingests and forwards end to end.

  The env-driven PET matrix is covered by bgp_peer_egress_v4; this feature
  focuses on the config-knob plumbing.

  Test Topology:
  ```
  z1 (AS65001) ── z2 (AS65002) ── z3 (AS65003)
   10.0.0.1/24    10.0.0.2/24     10.0.0.3/24
   origin         shards: 4       peer
                  peer-task: true
                  (from config)
  ```
  All three on bridge br0. z1 originates 10.10.10.0/24 + 10.10.11.0/24.

  Scenario: z2 reads both shards and peer-task from config and the speakers establish
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
    # Both knobs resolved from config (no env vars were set).
    Then the zebra-rs log in namespace "z2" should contain "BGP RIB sharding: 4 shards (from config)"
    And the zebra-rs log in namespace "z2" should contain "BGP per-peer egress task: enabled (from config)"
    And BGP session in "z2" to "10.0.0.1" should be "Established"
    And BGP session in "z2" to "10.0.0.3" should be "Established"

  Scenario: routes propagate through the config-driven per-peer egress
    Given the test topology exists
    # z1 originates; z2 must ingest (pool) and advertise to z3 through the
    # per-peer egress task — proving the config-driven PET egress is
    # functional, not just spawned.
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
