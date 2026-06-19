@serial
@bgp_unnumbered_summary
Feature: BGP unnumbered neighbor visible in summaries before any session
  As a network operator bringing up BGP over IPv6-only point-to-point
  links, I want a configured `interface-neighbor` to appear in
  `show bgp summary` (as Idle) even when the remote node has never been
  reachable, so that mis-cabled or not-yet-deployed neighbors are
  diagnosable from the summary instead of silently absent.

  Interface-keyed peers are normally materialized only when the
  remote's Router Advertisement surfaces its link-local. This feature
  pins the dormant-materialization path: config + link knowledge alone
  must create the operator-visible peer (FRR behaves the same way).

  Test Topology (point-to-point veth; z2 exists only to hold the other
  veth end — it never runs zebra-rs, so z1 never sees an RA):
  ```
        (i1)                                   (i1)
    ┌────┴────┐                            ┌─────────┐
    │   z1    │────────── P2P ─────────────│   z2    │
    │ AS65001 │      no RA, no session     │ (no     │
    │ id 1.1. │                            │ daemon) │
    │   1.1   │                            └─────────┘
    └─────────┘
  ```

  Scenario: Setup topology
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"
    And I wait 2 seconds

  Scenario: A never-connected interface-neighbor is listed as a dormant Idle peer
    Given the test topology exists
    # The trailing space pins the fixed-width Neighbor column. The peer
    # has no remote link-local yet, so its row must carry the Idle
    # state, and the per-AFI summary must list it too.
    Then show command "show bgp summary" in namespace "z1" should contain "i1 "
    And show command "show bgp summary" in namespace "z1" should contain "Idle"
    And show command "show bgp ipv4 summary" in namespace "z1" should contain "i1 "
    And show command "show bgp neighbor i1" in namespace "z1" should contain "BGP neighbor on i1:"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
