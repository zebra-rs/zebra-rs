@serial
@ospfv2_nssa
Feature: OSPFv2 NSSA (Not-So-Stubby Area) Type-7 origination and translation
  As a network operator
  I want zebra-rs to support OSPFv2 NSSA areas — N-bit adjacency
  negotiation, Type-7 (NSSA-AS-External) origination from an internal
  ASBR, intra-NSSA Type-7 route install, the ABR's RFC 3101
  Type-7->Type-5 translation into the rest of the OSPF domain, and a
  default Type-7 injected by the ABR — so that an external prefix born
  inside an NSSA is reachable both inside the area and across the
  backbone, while the area still refuses to carry Type-5 AS-External.

  Four routers, two areas. The backbone (0.0.0.0) holds the ABR a and
  a pure backbone router b. The NSSA (0.0.0.1) hangs off a as a
  hub-and-spoke: the ASBR c and the plain internal router d both peer
  only with a.

  Test Topology:
  ```
            area 0.0.0.0 (backbone)
      b (10.0.0.2) ---- 10.0.12.0/30 ---- a (ABR, 10.0.0.1)
                                          |  translator + default-originate
                                  area 0.0.0.1 (NSSA)
                       10.0.13.0/30 |        | 10.0.14.0/30
                              etha  |        |  etha
                         c (ASBR, 10.0.0.3)  d (10.0.0.4)
                         redistribute        plain internal
                         connected -> Type-7

    on router X the interface toward router Y is named "ethY".
    loopbacks: a .1  b .2  c .3  d .4  (10.0.0.X/32).
  ```

  The external prefix is a secondary loopback (192.168.1.1/32) added to
  c's lo AFTER zebra-rs starts; it is not registered under any OSPF
  area, so it enters OSPF only via c's per-area `redistribute connected`
  as a Type-7. c is a pure ASBR (not an ABR), so it sets the Type-7
  P-bit. The flood is area-scoped: d installs it directly, and the ABR
  a — the elected (sole-ABR, default `candidate` role) NSSA translator —
  re-originates it as a Type-5 AS-External into the backbone, where b
  installs it. b carries no NSSA link, so a Type-5 is the only way the
  prefix can reach it: its presence on b is the proof the translator ran.

  The metric is a flat [20] (E2 / type-2) everywhere — on d (Type-7)
  and on b (translated Type-5) alike — because E2 uses the LSA metric
  verbatim, independent of distance to the originator.

  Scenario: Internal ASBR Type-7 is installed in-area and translated to Type-5 on the backbone
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I create namespace "d"
    # Backbone link a-b, NSSA spokes a-c and a-d.
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I connect namespace "a" interface "ethc" to namespace "c" interface "etha"
    And I connect namespace "a" interface "ethd" to namespace "d" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "c"
    And I start zebra-rs in namespace "d"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "c.yaml" to namespace "c"
    And I apply config "d.yaml" to namespace "d"
    # Secondary loopback on c: the external prefix redistributed into
    # the NSSA as a Type-7. Not under any OSPF area, so it can only
    # enter via `redistribute connected`.
    And I add address "192.168.1.1/32" to interface "lo" in namespace "c"
    # Allow Hellos + DBD on every link (N-bit must match on the NSSA
    # links), then Type-7 origination + flood, the ABR's Type-7->Type-5
    # translation + AS-wide flood, and SPF/route install everywhere.
    And I wait 60 seconds

    # --- Adjacencies are Full on every link (the NSSA links only come
    #     up when the N-bit matches between a and c / a and d). ---
    Then show command "show ip ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ip ospf neighbor" in namespace "a" should contain "10.0.0.2"
    And show command "show ip ospf neighbor" in namespace "a" should contain "10.0.0.3"
    And show command "show ip ospf neighbor" in namespace "a" should contain "10.0.0.4"
    And show command "show ip ospf neighbor" in namespace "c" should contain "Full"
    And show command "show ip ospf neighbor" in namespace "c" should contain "10.0.0.1"

    # --- Type-7 inside the NSSA: d (plain internal router) installs the
    #     external prefix straight from c's Type-7, E2 metric [20]. ---
    And show command "show ip ospf route" in namespace "d" should contain "192.168.1.1/32"
    And show command "show ip ospf route" in namespace "d" should contain "[20]"

    # --- The headline: Type-7 -> Type-5 translation at the ABR. b is in
    #     the backbone only, so it can learn 192.168.1.1/32 ONLY as a
    #     translated Type-5 (the Type-7 never leaves the NSSA). Same E2
    #     metric [20], carried verbatim across the translation. ---
    And show command "show ip ospf route" in namespace "b" should contain "192.168.1.1/32"
    And show command "show ip ospf route" in namespace "b" should contain "[20]"

    # --- ABR default-originate: a injects a default Type-7 into the
    #     NSSA, so both internal routers hold a 0.0.0.0/0. ---
    And show command "show ip ospf route" in namespace "c" should contain "0.0.0.0/0"
    And show command "show ip ospf route" in namespace "d" should contain "0.0.0.0/0"

    # --- NSSA still accepts Type-3: d learns the backbone loopback as an
    #     inter-area summary (it is not totally stubby). ---
    And show command "show ip ospf route" in namespace "d" should contain "10.0.0.2/32"

    # --- End-to-end reachability. ---
    # Backbone host b reaches the NSSA-internal external prefix: the
    # translated Type-5 routes b -> a, then a (which holds the Type-7
    # route) -> c, proving translation AND forwarding.
    And ping from "b" to "192.168.1.1" should succeed
    # NSSA internal host d reaches the backbone loopback (inter-area),
    # and the external prefix (intra-NSSA Type-7).
    And ping from "d" to "10.0.0.2" should succeed
    And ping from "d" to "192.168.1.1" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "c"
    And I stop zebra-rs in namespace "d"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "c"
    And I delete namespace "d"
    Then the test environment should be clean
