@serial
@bgp_egress_group_task
Feature: BGP per-update-group egress task lifecycle (migration Phase 0)

  Phase 0 of the per-update-group egress-task migration
  (docs/design/bgp-egress-group-task-migration.md). At
  ZEBRA_BGP_EGRESS_GROUP_TASK=1 the speaker spawns one egress task per
  update group, tracking the group's members from the attach/detach
  machinery. Phase 0 is IDLE — the task routes no egress yet (that is
  Phase 1) — so the egress output is unchanged; this feature only proves the
  task LIFECYCLE: a group forming spawns its task, and sessions/teardown are
  undisturbed.

  z2 is the device under test, started with the egress group task. When its
  eBGP neighbors z1 and z3 establish, z2 forms at least one update group, so
  its log must show the group-task spawn. The sessions establishing proves
  the spawn/track wiring does not disrupt the session machinery.

  Test Topology:
  ```
  z1 (AS65001) ── z2 (AS65002) ── z3 (AS65003)
   10.0.0.1/24    10.0.0.2/24     10.0.0.3/24
                  egress group
                  task (gate-on)
  ```
  All three on bridge br0.

  Scenario: a group forming spawns its egress task; sessions are undisturbed
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "10.0.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "10.0.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "10.0.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2" with egress group task
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    # A group forms once a peer establishes, so the task must have spawned.
    Then the zebra-rs log in namespace "z2" should contain "BGP egress group task: spawned"
    And BGP session in "z2" to "10.0.0.1" should be "Established"
    And BGP session in "z2" to "10.0.0.3" should be "Established"

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
