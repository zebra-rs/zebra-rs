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

  Scenario: routes propagate through the group task (Phase 1b event-driven advertise)
    Given the test topology exists
    # All speakers are up before any route exists, so z1's origination is an
    # event-driven advertise: z2's reduce fans one delta to the (single) update
    # group serving z3, whose task encodes once and sends to z3 (split-horizon
    # excludes z1, the source). z2's own `show bgp ipv4` reads its Loc-RIB.
    When I apply config "z1-routes.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp ipv4" in namespace "z2" should contain "10.10.10.0/24"
    And show command "show bgp ipv4" in namespace "z2" should contain "10.10.11.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.10.10.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.10.11.0/24"

  Scenario: an event-driven withdraw propagates through the group task (Phase 1b)
    Given the test topology exists
    # z1 re-originates only 10.10.11.0/24 (dropping .10). The reduce's
    # apply_ipv4_advertise_job handles BOTH the advertise and the withdraw, so
    # the group task must withdraw .10 from z3 while .11 stays — proving the
    # gate-on event path is coherent (advertise + withdraw both through the
    # task, the update-group flush bypassed). .11 staying is the positive
    # control so the negative assertion isn't vacuous.
    When I apply config "z1-withdraw.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp ipv4" in namespace "z3" should not contain "10.10.10.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.10.11.0/24"

  Scenario: a peer-down withdraw propagates through the group task (Phase 2)
    Given the test topology exists
    # z3 still holds .11 (positive control). Stopping z1 makes z2 clean z1's
    # routes; the group task must withdraw .11 from z3. This is the peer-down
    # path (route_clean), distinct from the event-driven withdraw above.
    Then show command "show bgp ipv4" in namespace "z3" should contain "10.10.11.0/24"
    When I stop zebra-rs in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "10.0.0.1" should not be "Established"
    And show command "show bgp ipv4" in namespace "z3" should not contain "10.10.11.0/24"

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
