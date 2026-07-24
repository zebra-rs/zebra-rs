@serial
@ospfv3_multi_area
Feature: OSPFv3 ABR originates Inter-Area-Prefix-LSAs across three areas
  As a network operator
  I want a zebra-rs OSPFv3 Area Border Router to condense each area's
  routes into Inter-Area-Prefix-LSAs (0x2003) flooded into its other
  areas — with backbone split-horizon and per-area SPF — so that
  routers in different non-backbone areas reach each other through
  the backbone. Mirrors ospfv2_multi_area for the v3 LSA model.

  Test Topology (v6 mirror of ospfv2_multi_area):
  ```
                 area 0.0.0.1                 area 0.0.0.2
                  e (2001:db8::5)              f (2001:db8::6)
                     |                            |
              2001:db8:15::/64             2001:db8:36::/64
                     | ethe                  ethf |
        ____________ a (ABR, 10.0.0.1) ........  c (ABR, 10.0.0.3) ____
       |   area 0   /|                            |\   area 0          |
   2001:db8:12::/64 /2001:db8:14::/64 (cost 20)   | 2001:db8:23::/64   |
       |           /  | etha                 ethd | 2001:db8:34::/64   |
       b (2001:db8::2) d (2001:db8::4) ___________/  (cost 20)         |
       |  \________ 2001:db8:24::/64 (b - d) ______/                   |
       \_______________________________________________________________|

    on router X the interface toward router Y is named "ethY".
    loopbacks: 2001:db8::X/128, router-ids 10.0.0.X (a=1 .. f=6).
  ```

  The cost-20 a-d and c-d links tie the two-hop alternative (a-b-d =
  c-b-d = 10+10), so d's loopback shows at metric 20 from a and c —
  with the default cost 10 the direct link would win at metric 10,
  making "metric 20" the deterministic proof the configured cost took.

  Scenario: Routers in two non-backbone areas reach each other through the backbone
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I create namespace "d"
    And I create namespace "e"
    And I create namespace "f"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I connect namespace "b" interface "ethc" to namespace "c" interface "ethb"
    And I connect namespace "a" interface "ethd" to namespace "d" interface "etha"
    And I connect namespace "c" interface "ethd" to namespace "d" interface "ethc"
    And I connect namespace "b" interface "ethd" to namespace "d" interface "ethb"
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
    # First Hellos + DBD on every link, then the multi-hop propagation:
    # c summarizes area 2 into the backbone, a re-advertises it into
    # area 1 (and the mirror for area 2), each step a flood + SPF.
    And I wait 60 seconds

    # --- Adjacencies are Full (backbone + both area uplinks). ---
    Then show command "show ospfv3 neighbor" in namespace "a" should contain "Full"
    And show command "show ospfv3 neighbor" in namespace "a" should contain "10.0.0.5"
    And show command "show ospfv3 neighbor" in namespace "e" should contain "Full"
    And show command "show ospfv3 neighbor" in namespace "e" should contain "10.0.0.1"
    And show command "show ospfv3 neighbor" in namespace "c" should contain "Full"
    And show command "show ospfv3 neighbor" in namespace "c" should contain "10.0.0.6"

    # --- The v3 inter-area machinery is visible in the LSDB. ---
    And show command "show ospfv3 database" in namespace "e" should contain "Inter-Area-Prefix-LSA"

    # --- Inter-area routes installed (prefixes ONLY reachable across
    #     an area boundary, so their presence proves 0x2003 import). ---
    # e (area 1) learns c (backbone) and f (area 2).
    And show command "show ospfv3 route" in namespace "e" should contain "2001:db8::3/128"
    And show command "show ospfv3 route" in namespace "e" should contain "2001:db8::6/128"
    # f (area 2) learns e (area 1) the same way.
    And show command "show ospfv3 route" in namespace "f" should contain "2001:db8::5/128"

    # --- Inter-area reachability end to end. ---
    And ping from "e" to "2001:db8::6" should succeed
    And ping from "f" to "2001:db8::5" should succeed
    And ping from "e" to "2001:db8::2" should succeed
    And ping from "a" to "2001:db8::6" should succeed

    # --- Cost-based path selection: d's loopback at metric 20 from
    #     both ABRs (10 default would make it metric 10). ---
    And show command "show ospfv3 route" in namespace "a" should contain "2001:db8::4/128 metric 20"
    And show command "show ospfv3 route" in namespace "c" should contain "2001:db8::4/128 metric 20"

  Scenario: Teardown topology
    # Separate scenario so cleanup still runs when a step above fails
    # (a failed step skips the rest of its own scenario only).
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
