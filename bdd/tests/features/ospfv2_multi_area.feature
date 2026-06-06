@serial
@ospfv2_multi_area
Feature: OSPFv2 multi-area routing across two Area Border Routers
  As a network operator
  I want zebra-rs to act as an OSPFv2 Area Border Router — originating a
  per-area Router-LSA and Type-3 Summary-LSAs — so that hosts in different
  non-backbone areas learn each other's prefixes through the backbone and
  are mutually reachable, with paths chosen by configured interface cost.

  Six routers in three areas. The backbone (area 0.0.0.0) holds a, b, c, d
  fully meshed-ish; a and c are the ABRs, each anchoring one non-backbone
  area. Area 0.0.0.1 hangs off a (internal router e); area 0.0.0.2 hangs
  off c (internal router f).

  Test Topology:
  ```
                 area 0.0.0.1                 area 0.0.0.2
                  e (10.0.0.5)                 f (10.0.0.6)
                     |                            |
                10.0.15.0/30                 10.0.36.0/30
                     | ethe                  ethf |
        ____________ a (ABR, 10.0.0.1) ........  c (ABR, 10.0.0.3) ____
       |   area 0   /|                            |\   area 0          |
       |           / |                            | \                  |
   10.0.12.0/30   /  10.0.14.0/30 (cost 20)       |  10.0.23.0/30      |
   (cost 10)     /   |                            |  (cost 10)         |
       |        /    | etha                  ethd | 10.0.34.0/30       |
       b (10.0.0.2)  d (10.0.0.4) ________________/  (cost 20)         |
       |  \________ 10.0.24.0/30 (cost 10) ________/                   |
       |              (b - d)                                          |
       \______________________________________________________________/

    backbone links + cost:
      a-b 10.0.12.0/30  cost 10      a-d 10.0.14.0/30  cost 20
      b-c 10.0.23.0/30  cost 10      c-d 10.0.34.0/30  cost 20
      b-d 10.0.24.0/30  cost 10
    on router X the interface toward router Y is named "ethY".
    loopbacks: a .1  b .2  c .3  d .4  e .5  f .6  (10.0.0.X/32).
  ```

  The cost-20 a-d and c-d links are the only non-default metrics. They are
  always tied (20) with the two-hop alternative (a-b-d = c-b-d = 10+10), so
  the direct link only ever shows up as an equal-cost path at metric 20 —
  had cost stayed at the default 10 the direct link would win outright at
  10. That metric is the deterministic proof the configured cost took
  effect.

  Inter-area reachability between e (area 1) and f (area 2) is the headline:
  it can only work if a and c each originate Type-3 summaries — a's of
  area 1 into the backbone, c re-advertising them into area 2, and the
  mirror image for f — so the ABR producer is exercised end to end.

  Scenario: Two ABRs glue three areas; inter-area routes form and resolve by cost
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I create namespace "d"
    And I create namespace "e"
    And I create namespace "f"
    # Backbone (area 0) links.
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I connect namespace "b" interface "ethc" to namespace "c" interface "ethb"
    And I connect namespace "c" interface "ethd" to namespace "d" interface "ethc"
    And I connect namespace "a" interface "ethd" to namespace "d" interface "etha"
    And I connect namespace "b" interface "ethd" to namespace "d" interface "ethb"
    # Non-backbone area uplinks: a->e (area 1), c->f (area 2).
    And I connect namespace "a" interface "ethe" to namespace "e" interface "etha"
    And I connect namespace "c" interface "ethf" to namespace "f" interface "ethc"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "c"
    And I start zebra-rs in namespace "d"
    And I start zebra-rs in namespace "e"
    And I start zebra-rs in namespace "f"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "c.yaml" to namespace "c"
    And I apply config "d.yaml" to namespace "d"
    And I apply config "e.yaml" to namespace "e"
    And I apply config "f.yaml" to namespace "f"
    # Allow first Hellos + DBD on every link, then the multi-hop Type-3
    # propagation: c summarizes area 2 into the backbone, a re-advertises
    # it into area 1 (and the mirror for area 2), each step a flood + SPF.
    And I wait 60 seconds

    # --- Adjacencies are Full (backbone + both area uplinks). ---
    Then show command "show ip ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ip ospf neighbor" in namespace "a" should contain "10.0.0.5"
    And show command "show ip ospf neighbor" in namespace "e" should contain "Full"
    And show command "show ip ospf neighbor" in namespace "e" should contain "10.0.0.1"
    And show command "show ip ospf neighbor" in namespace "c" should contain "Full"
    And show command "show ip ospf neighbor" in namespace "c" should contain "10.0.0.6"

    # --- Inter-area routes are installed (a prefix that is ONLY reachable
    #     across an area boundary, so its presence proves Type-3 import). ---
    # e (area 1) learns c (backbone) and f (area 2) as inter-area routes.
    And show command "show ip ospf route" in namespace "e" should contain "10.0.0.3/32"
    And show command "show ip ospf route" in namespace "e" should contain "10.0.0.6/32"
    # f (area 2) learns e (area 1) the same way.
    And show command "show ip ospf route" in namespace "f" should contain "10.0.0.5/32"

    # --- Inter-area reachability end to end. ---
    # Area 1 host e to area 2 host f and back — the headline cross-area ping.
    And ping from "e" to "10.0.0.6" should succeed
    And ping from "f" to "10.0.0.5" should succeed
    # Area 1 host to a backbone loopback, and an ABR to a remote-area host.
    And ping from "e" to "10.0.0.2" should succeed
    And ping from "a" to "10.0.0.6" should succeed

    # --- Cost-based path selection. ---
    # The cost-20 a-d link ties the two-hop a-b-d path at metric 20, so a's
    # route to d (10.0.0.4) shows an equal-cost path via the direct link
    # (d's a-d address 10.0.14.2) at [20]; with the default cost 10 the
    # direct link would instead win at [10], so "[20] via 10.0.14.2" only
    # appears when the configured cost is honored.
    And show command "show ip ospf route" in namespace "a" should contain "[20] via 10.0.14.2"
    # Mirror proof for the cost-20 c-d link (d's c-d address 10.0.34.2).
    And show command "show ip ospf route" in namespace "c" should contain "[20] via 10.0.34.2"

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "c"
    And I stop zebra-rs in namespace "d"
    And I stop zebra-rs in namespace "e"
    And I stop zebra-rs in namespace "f"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "c"
    And I delete namespace "d"
    And I delete namespace "e"
    And I delete namespace "f"
    Then the test environment should be clean
