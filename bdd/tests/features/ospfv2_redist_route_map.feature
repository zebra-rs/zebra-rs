@serial
@ospfv2_redist_route_map
Feature: OSPFv2 redistribution route-map filters and re-applies dynamically
  As a network operator
  I want `redistribute <source> route-map <name>` to filter and
  modify routes entering OSPF as Type-5 AS-External LSAs — and I
  want edits to the route-map (or a prefix-set it references) to
  re-apply LIVE, originating newly-permitted prefixes and flushing
  newly-denied ones without touching the OSPF session.

  Test Topology:
  ```
    r1 -- 10.0.12.0/30 -- r2 (redistribute connected route-map RM)
    r2 dummies (not OSPF-enabled): d1 10.1.1.0/24, d2 10.2.2.0/24
    RM: permit prefix-set PS, set metric 555; implicit deny rest.
  ```
  The scenarios share one topology: setup, two live edits, teardown
  (mirrors bgp_policy_dynamic_update).

  Scenario: Setup — route-map admits only the prefix-set, with set metric
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I connect namespace "r1" interface "ethb" to namespace "r2" interface "etha"
    And I create dummy interface "d1" with address "10.1.1.1/24" in namespace "r2"
    And I create dummy interface "d2" with address "10.2.2.1/24" in namespace "r2"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2-initial.yaml" to namespace "r2"
    And I wait 25 seconds

    Then show command "show ospf neighbor" in namespace "r1" should contain "Full"
    # PS-permitted prefix arrives as an external at the set metric.
    And show command "show ospf route" in namespace "r1" should eventually contain "10.1.1.0/24          [555] via 10.0.12.2"
    # Everything else — the other dummy AND the transit /30 the
    # implicit deny catches — stays out.
    And show command "show ospf route" in namespace "r1" should not contain "10.2.2.0/24"

  Scenario: Live edit — adding a prefix to the referenced prefix-set originates it
    # One incremental prefix-set change; the policy actor's cascade
    # re-pushes the bound route-map and OSPF re-filters live.
    When I apply config "r2-both.yaml" to namespace "r2"
    Then show command "show ospf route" in namespace "r1" should eventually contain "10.2.2.0/24          [555] via 10.0.12.2"
    And show command "show ospf route" in namespace "r1" should contain "10.1.1.0/24          [555] via 10.0.12.2"

  Scenario: Live edit — removing a prefix flushes its Type-5 LSA
    When I apply config "r2-other.yaml" to namespace "r2"
    Then show command "show ospf route" in namespace "r1" should eventually not contain "10.1.1.0/24"
    And show command "show ospf route" in namespace "r1" should contain "10.2.2.0/24          [555] via 10.0.12.2"

  Scenario: Teardown topology
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    Then the test environment should be clean
