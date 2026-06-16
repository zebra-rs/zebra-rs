@serial
@bgp_egress_group_task
Feature: BGP per-update-group egress task (migration Phases 0-3)

  Per-update-group egress-task migration
  (docs/design/bgp-egress-group-task-migration.md). At
  ZEBRA_BGP_EGRESS_GROUP_TASK=1 the v4-unicast egress runs in one task per
  update group (M tasks, not N peers): the task owns the group adj_out,
  encodes each best path once, and fans the bytes to its member peers,
  excluding the path's source (split-horizon).

  This feature exercises the gate-on egress matrix through the group task:
    * Phase 0/1a — a forming group spawns its task (lifecycle).
    * Phase 1b — z1's origination is an event-driven advertise that reaches
      z3 through the task; an event-driven withdraw drops a route.
    * Phase 2 — peer-down (z1 stops) withdraws through the task.
    * Phase 3 — z4 establishes AFTER the routes exist (a late peer). It must
      receive them on session-up sync, and — the coherence check — a later
      withdraw / peer-down must reach z4 too, which holds only if the group
      adj_out reflects what z4 was sync'd.

  z3 and z4 share one update group (same eBGP egress identity; remote-AS is
  not part of the signature). z2 is the device under test, started with the
  egress group task.

  Test Topology:
  ```
                        ┌── z3 (AS65003)  early peer
  z1 (AS65001) ── z2 (AS65002) ──┤
                  egress group   └── z4 (AS65004)  late peer (Phase 3)
                  task (gate-on)
  ```
  All four on bridge br0. z1 originates 10.10.10.0/24 + 10.10.11.0/24.

  Scenario: a group forming spawns its egress task; early speakers establish
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "10.0.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "10.0.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "10.0.0.3/24" on bridge "br0"
    And I create namespace "z4" with IP "10.0.0.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2" with egress group task
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then the zebra-rs log in namespace "z2" should contain "BGP egress group task: spawned"
    And BGP session in "z2" to "10.0.0.1" should be "Established"
    And BGP session in "z2" to "10.0.0.3" should be "Established"

  Scenario: routes propagate through the group task (Phase 1b event-driven advertise)
    Given the test topology exists
    When I apply config "z1-routes.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp ipv4" in namespace "z2" should contain "10.10.10.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.10.10.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.10.11.0/24"

  Scenario: advertised-routes reads the group adj_out, split-horizon filtered (Phase 5)
    Given the test topology exists
    # z2's v4 Adj-RIB-Out to a peer lives in its update group's task at gate-on,
    # not on the peer. `show ... advertised-routes` must request it from the
    # group task: z3 was advertised .10/.11, and — split-horizon — z1 (the
    # source) was advertised neither.
    Then show command "show bgp neighbors 10.0.0.3 advertised-routes" in namespace "z2" should contain "10.10.10.0/24"
    And show command "show bgp neighbors 10.0.0.3 advertised-routes" in namespace "z2" should contain "10.10.11.0/24"
    And show command "show bgp neighbors 10.0.0.1 advertised-routes" in namespace "z2" should not contain "10.10.10.0/24"

  Scenario: a late peer z4 gets the routes on session-up sync (Phase 3)
    Given the test topology exists
    # z4's daemon starts now — AFTER z2 already holds z1's routes — so z4
    # learns them via z2's route_sync_ipv4 dump while it joins z3's update
    # group. z4 seeing both prefixes proves the late-join sync path.
    When I start zebra-rs in namespace "z4"
    And I apply config "z4.yaml" to namespace "z4"
    And I wait 15 seconds for BGP to operate
    Then BGP session in "z2" to "10.0.0.4" should be "Established"
    And show command "show bgp ipv4" in namespace "z4" should contain "10.10.10.0/24"
    And show command "show bgp ipv4" in namespace "z4" should contain "10.10.11.0/24"

  Scenario: a clear soft-out re-fans the group through the task (Phase 4)
    Given the test topology exists
    # `clear ... soft out` on z2 for z3 triggers route_soft_out_peer, which at
    # gate-on refreshes the group's member ctxs and re-fans the v4 Loc-RIB
    # through the task. With no policy change the routes are unchanged, so z3
    # (and z4, its group-mate) keep them — proving the soft-out re-fan
    # re-advertises rather than dropping or going through the old flush.
    When I run "clear bgp ipv4 neighbor 10.0.0.3 soft out" in namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then show command "show bgp ipv4" in namespace "z3" should contain "10.10.10.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.10.11.0/24"
    And show command "show bgp ipv4" in namespace "z4" should contain "10.10.10.0/24"

  Scenario: z2's `show bgp ipv4 summary` PfxSnt comes from the group task (N=1, group gate only)
    Given the test topology exists
    # At gate-on the v4 Adj-RIB-Out lives in the update group's egress task, not
    # on the peer, so the summary's PfxSnt read main-side printed 0. N=1 here
    # (no shards), so this exercises the group branch ALONE — the summary
    # intercept must fire on the egress-group-task gate, query the group's
    # CountAdjOut, and subtract each member's split-horizoned own paths. z3 and
    # z4 were each advertised z1's two routes (PfxSnt 2 -> "0/2"); z1, the
    # source, got none back (PfxSnt 0) while z2 received its two (PfxRcd 2 read
    # from the main shard at N=1 -> "2/0"). Under the bug PfxSnt is 0, so "0/2"
    # never appears.
    Then show command "show bgp ipv4 summary" in namespace "z2" should contain "0/2"
    And show command "show bgp ipv4 summary" in namespace "z2" should contain "2/0"

  Scenario: an event-driven withdraw reaches BOTH the early and the late member (Phase 3 coherence)
    Given the test topology exists
    # z1 re-originates only .11. The group task must withdraw .10 from z3 AND
    # z4 — z4 too only if the group adj_out reflects what z4 was sync'd (the
    # late-member coherence the per-peer route_sync would otherwise miss).
    When I apply config "z1-withdraw.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp ipv4" in namespace "z3" should not contain "10.10.10.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.10.11.0/24"
    And show command "show bgp ipv4" in namespace "z4" should not contain "10.10.10.0/24"
    And show command "show bgp ipv4" in namespace "z4" should contain "10.10.11.0/24"

  Scenario: peer-down withdraws through the group task to both members (Phase 2/3)
    Given the test topology exists
    Then show command "show bgp ipv4" in namespace "z4" should contain "10.10.11.0/24"
    When I stop zebra-rs in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "10.0.0.1" should not be "Established"
    And show command "show bgp ipv4" in namespace "z3" should not contain "10.10.11.0/24"
    And show command "show bgp ipv4" in namespace "z4" should not contain "10.10.11.0/24"

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
