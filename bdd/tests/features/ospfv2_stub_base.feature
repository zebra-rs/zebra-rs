@serial
@ospfv2_stub_base
Feature: OSPFv2 stub area drops Type-5 AS-External while keeping inter-area routes
  As a network operator
  I want zebra-rs to support OSPFv2 stub areas — E-bit adjacency
  negotiation, AS-External (Type-5) LSAs excluded from the area, and
  inter-area Type-3 summaries still flooded in — so that a stub router
  learns inter-area destinations but is shielded from the external LSDB.

  Three routers, two areas. The backbone (0.0.0.0) holds the ABR a and
  the ASBR b; the stub (0.0.0.1) holds the internal router c hanging
  off a.

  Test Topology:
  ```
        area 0.0.0.0 (backbone)              area 0.0.0.1 (stub)
    b (ASBR, 10.0.0.2) -- 10.0.12.0/30 -- a (ABR, 10.0.0.1) -- 10.0.13.0/30 -- c (10.0.0.3)
    redistribute connected                                                      internal
    -> Type-5

    on router X the interface toward router Y is named "ethY".
    loopbacks: a .1  b .2  c .3  (10.0.0.X/32).
  ```

  b redistributes a connected network (192.168.1.0/24) on a standalone
  dummy interface "cust0" (NOT an OSPF interface, so it is a genuine
  external — not an intra-area stub that would summarize as a Type-3) as
  a Type-5 AS-External LSA. The backbone router a installs it, but
  `flood_lsa_through_as` skips stub areas, so the Type-5 never reaches c
  — and external prefixes are not re-advertised as Type-3 either. The
  backbone loopback 10.0.0.2/32, by contrast, IS summarized into the
  stub as a Type-3, so c reaches it across the area boundary.

  Scenario: Stub router learns inter-area Type-3 but never the Type-5 external
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I connect namespace "a" interface "ethc" to namespace "c" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "c"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "c.yaml" to namespace "c"
    # External network on the ASBR b's non-OSPF dummy interface: the
    # prefix redistributed as a Type-5.
    And I create dummy interface "cust0" with address "192.168.1.1/24" in namespace "b"
    # Allow Hellos + DBD (E-bit must match on the stub link), Type-5
    # origination + backbone flood, Type-3 summary into the stub, and
    # SPF/route install.
    And I wait 60 seconds

    # --- Adjacencies are Full (the stub link only comes up when the
    #     E-bit matches between a and c). ---
    Then show command "show ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ospf neighbor" in namespace "a" should contain "10.0.0.2"
    And show command "show ospf neighbor" in namespace "a" should contain "10.0.0.3"
    And show command "show ospf neighbor" in namespace "c" should contain "Full"
    And show command "show ospf neighbor" in namespace "c" should contain "10.0.0.1"

    # --- The backbone router a installs the Type-5 external. ---
    And show command "show ospf route" in namespace "a" should contain "192.168.1.0/24"

    # --- The stub router c learns the backbone loopback as an inter-area
    #     Type-3 summary (stub still floods Type-3 inward). ---
    And show command "show ospf route" in namespace "c" should contain "10.0.0.2/32"
    # --- But c must NOT learn the Type-5 external: stub areas exclude
    #     AS-External, and externals are not re-advertised as Type-3. ---
    And show command "show ospf route" in namespace "c" should not contain "192.168.1.0/24"

    # --- Reachability across the area boundary works (Type-3); the ABR,
    #     which holds the Type-5, reaches the external. ---
    And ping from "c" to "10.0.0.2" should succeed
    And ping from "a" to "192.168.1.1" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "c"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "c"
    Then the test environment should be clean
