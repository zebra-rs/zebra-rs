@serial
@bgp_shard_policy
Feature: BGP inbound policy through the RIB shards (ZEBRA_BGP_SHARDS>1)

  As a network operator running BGP with the RIB partitioned across
  worker shards (ZEBRA_BGP_SHARDS>1), I want per-neighbor inbound policy
  to be applied by the shard workers exactly as on the synchronous N=1
  path, so that sharding stays transparent to policy.

  This exercises RIB sharding Phase C + PolicyReplace + the dropped N=1
  par_iter: z2 runs with 4 shards, so its inbound policy is replicated to
  every shard (a peer's prefixes hash across all of them) and applied in
  `compute_policy` on the shard worker — not on the main task.

  Correctness is observed DOWNSTREAM on z3, and only on the N>1
  steady-state advertise path (the N>1 `show`, soft-in replay, and
  new-peer sync are known gaps): policy is set at startup, z3 is brought
  up FIRST, and z1's routes are originated only AFTER every session is
  Established, so z2 processes them live (ingest → shard → reduce →
  advertise to the already-up z3). One inbound policy permits 10.0.0.1/32
  and implicit-denies 10.0.0.2/32 — a positive and a negative control in
  one shot: z3 must see .1 (sharded permit + advertise works) but never
  .2 (sharded deny works; before PolicyReplace the shard default-permitted
  and .2 would have leaked).

  Test Topology:
  ```
  z1 (AS65001) ── z2 (AS65002, 4 shards) ── z3 (AS65003)
  192.168.0.1/24   192.168.0.2/24           192.168.0.3/24
  ```
  All three on bridge br0.

  Config files:
  - z1-base.yaml: AS 65001, peers z2, originates nothing yet.
  - z1-routes.yaml: adds network 10.0.0.1/32 + 10.0.0.2/32 (originated
    once the sessions are up, so z2 sees them on the live update path).
  - z2.yaml: AS 65002, peers z1 (inbound policy IN-POL permitting only
    10.0.0.1/32) + z3, 4 shards.
  - z3.yaml: AS 65003, peers z2 — the downstream observer (N=1, `show`
    works).

  Scenario: Setup sessions with z2 sharded, before any routes exist
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2" with 4 shards
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z2" to "192.168.0.3" should be "Established"

  Scenario: z1 originates routes; sharded inbound policy permits .1, denies .2
    Given the test topology exists
    When I apply config "z1-routes.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then BGP route in "z3" has "10.0.0.1/32"
    And BGP route in "z3" does not have "10.0.0.2/32"

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
