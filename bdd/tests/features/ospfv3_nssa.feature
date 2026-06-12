@serial
@ospfv3_nssa
Feature: OSPFv3 NSSA (Not-So-Stubby Area) Type-7 origination and translation
  As a network operator
  I want zebra-rs to support OSPFv3 NSSA areas — N-bit adjacency, Type-7
  (NSSA-LSA) origination from an internal ASBR via redistribute
  connected, intra-NSSA Type-7 route install, and the ABR's RFC 5340 /
  RFC 3101 Type-7->Type-5 translation into the backbone — so that an IPv6
  external prefix born inside an NSSA reaches both the area and the rest
  of the OSPFv3 domain.

  This is the IPv6 counterpart of @ospfv2_nssa. Four routers, two areas:
  the backbone (0.0.0.0) holds the ABR a and a pure backbone router b;
  the NSSA (0.0.0.1) hangs off a as a hub-and-spoke with the ASBR c and
  the plain internal router d.

  Test Topology:
  ```
            area 0.0.0.0 (backbone)
      b (10.0.0.2) -- 2001:db8:12::/64 -- a (ABR, 10.0.0.1)
                                          |  translator + default-originate
                                  area 0.0.0.1 (NSSA)
                     2001:db8:13::/64 |        | 2001:db8:14::/64
                       c (ASBR, 10.0.0.3)      d (10.0.0.4)
                       redistribute            plain internal
                       connected -> Type-7

    on router X the interface toward router Y is named "ethY".
    loopbacks: 2001:db8::X/128 (X = router-id last octet).
  ```

  The external prefix is a connected network (2001:db8:dead::/64) on a
  standalone dummy interface "cust0" on c — NOT on any OSPF-enabled
  interface, so it is a genuine external that enters OSPFv3 only via
  `redistribute connected` as a Type-7. c is a pure ASBR (not an ABR),
  so it sets the Type-7 P-bit in the prefix-options. d installs it
  directly (area-scoped flood); a — the elected (sole-ABR, default
  `candidate` role) translator — re-originates it as a Type-5
  AS-External into the backbone, where b installs it. b carries no NSSA
  link, so a translated Type-5 is the only way the prefix reaches it.

  Scenario: Internal ASBR Type-7 is installed in-area and translated to Type-5 on the backbone
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I create namespace "d"
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
    # The external network on c's non-OSPF dummy interface — redistributed
    # into the NSSA as a Type-7.
    And I create dummy interface "cust0" with address "2001:db8:dead::1/64" in namespace "c"
    And I wait 60 seconds

    # --- Adjacencies are Full on every link (the NSSA links require the
    #     N-bit to match between a and c / a and d). ---
    Then show command "show ospfv3 neighbor" in namespace "a" should contain "Full"
    And show command "show ospfv3 neighbor" in namespace "a" should contain "10.0.0.2"
    And show command "show ospfv3 neighbor" in namespace "a" should contain "10.0.0.3"
    And show command "show ospfv3 neighbor" in namespace "a" should contain "10.0.0.4"
    And show command "show ospfv3 neighbor" in namespace "c" should contain "Full"
    And show command "show ospfv3 neighbor" in namespace "c" should contain "10.0.0.1"

    # --- Type-7 inside the NSSA: d installs the external prefix straight
    #     from c's Type-7. ---
    And show command "show ospfv3 route" in namespace "d" should contain "2001:db8:dead::/64"

    # --- The headline: Type-7 -> Type-5 translation at the ABR. b is in
    #     the backbone only, so it can learn 2001:db8:dead::/64 ONLY as a
    #     translated Type-5 (the Type-7 never leaves the NSSA). ---
    And show command "show ospfv3 route" in namespace "b" should contain "2001:db8:dead::/64"

    # --- ABR default-originate: a injects a default Type-7 into the NSSA,
    #     so both internal routers hold a ::/0. ---
    And show command "show ospfv3 route" in namespace "c" should contain "::/0"
    And show command "show ospfv3 route" in namespace "d" should contain "::/0"

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

  # Translator-role `never`: the ABR refuses to translate. The Type-7
  # still floods the NSSA and d installs it, but with no translator the
  # prefix never becomes a Type-5, so the backbone-only router never
  # learns it. Negative control for the first scenario's translation.
  Scenario: Translator-role never keeps the Type-7 in-area and out of the backbone
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I create namespace "d"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I connect namespace "a" interface "ethc" to namespace "c" interface "etha"
    And I connect namespace "a" interface "ethd" to namespace "d" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "c"
    And I start zebra-rs in namespace "d"
    # Only a differs: nssa-translator-role = never.
    And I apply config "a_never.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "c.yaml" to namespace "c"
    And I apply config "d.yaml" to namespace "d"
    And I create dummy interface "cust0" with address "2001:db8:dead::1/64" in namespace "c"
    And I wait 60 seconds

    # --- Intra-NSSA Type-7 install is unchanged: d still learns it. ---
    Then show command "show ospfv3 route" in namespace "d" should contain "2001:db8:dead::/64"
    # --- But with translation disabled the prefix never reaches the
    #     backbone: b must NOT contain it. ---
    And show command "show ospfv3 route" in namespace "b" should not contain "2001:db8:dead::/64"

    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "c"
    And I stop zebra-rs in namespace "d"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "c"
    And I delete namespace "d"
    Then the test environment should be clean
