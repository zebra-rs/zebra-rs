@serial
@ospfv2_as_external
Feature: OSPFv2 AS-External (Type-5) LSA origination with E1 and E2 metric types
  As a network operator
  I want zebra-rs to act as an OSPFv2 ASBR — originating Type-5 AS-External
  LSAs from redistributed connected routes — so that routers in all areas
  install the external prefix, and the metric type (E1 vs E2) is correctly
  computed and varies by observer location for E1.

  Same six-router three-area topology as ospfv2_multi_area:
  Area 0: a (ABR), b (ASBR), c (ABR), d.
  Area 0.0.0.1: a (ABR), e (internal).
  Area 0.0.0.2: c (ABR), f (internal).

  Router b is the ASBR in backbone area 0.  A connected network
  (192.168.1.0/24) on a standalone dummy interface "cust0" is added to b
  after zebra-rs starts.  It is NOT on any OSPF-enabled interface, so it
  is a genuine external route — it enters the OSPF domain exclusively via
  `redistribute connected` as a Type-5 AS-External LSA.  (An address on
  an OSPF-enabled interface would instead be advertised as an intra-area
  stub and summarized as a Type-3, which would win over the Type-5 and
  mask the AS-External path being tested.)

  E2 metric (type 2): the installed metric equals the LSA's external metric
  (20) regardless of the observer's distance to the ASBR — the same [20]
  appears on a (backbone, 1 hop), e (area 1, 2 hops), and f (area 2, 2 hops).

  E1 metric (type 1): the installed metric equals SPF-cost-to-ASBR plus the
  external metric.  b is connected to a and c at cost 10, so backbone routers
  one hop away see [30] (10 + 20).  e reaches b via a (10) then via Type-4
  from a (10), total ASBR cost 20, so it sees [40] (20 + 20).

  Interface naming: on router X the interface toward router Y is "ethY".
  Loopbacks: 10.0.0.X/32.

  Scenario: E2 metric — same external metric from all observers
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I create namespace "d"
    And I create namespace "e"
    And I create namespace "f"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I connect namespace "b" interface "ethc" to namespace "c" interface "ethb"
    And I connect namespace "c" interface "ethd" to namespace "d" interface "ethc"
    And I connect namespace "a" interface "ethd" to namespace "d" interface "etha"
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
    And I apply config "b_e2.yaml" to namespace "b"
    And I apply config "c.yaml" to namespace "c"
    And I apply config "d.yaml" to namespace "d"
    And I apply config "e.yaml" to namespace "e"
    And I apply config "f.yaml" to namespace "f"
    # A connected network on a non-OSPF dummy interface: a genuine
    # external prefix redistributed as a Type-5 (not an intra-area stub).
    And I create dummy interface "cust0" with address "192.168.1.1/24" in namespace "b"
    # Allow time for OSPF to converge, originate Type-3/4/5 LSAs, and install
    # external routes in all areas via flooding + SPF.
    And I wait 60 seconds

    # --- All areas install the external prefix with the E2 metric (20). ---
    # Same metric on every observer proves type-2: external-metric only.
    Then show command "show ip ospf route" in namespace "a" should contain "192.168.1.0/24"
    And show command "show ip ospf route" in namespace "a" should contain "[20]"
    And show command "show ip ospf route" in namespace "c" should contain "192.168.1.0/24"
    And show command "show ip ospf route" in namespace "c" should contain "[20]"
    # e is in area 0.0.0.1 — needs Type-4 from ABR a to find ASBR b.
    And show command "show ip ospf route" in namespace "e" should contain "192.168.1.0/24"
    And show command "show ip ospf route" in namespace "e" should contain "[20]"
    # f is in area 0.0.0.2 — needs Type-4 from ABR c to find ASBR b.
    And show command "show ip ospf route" in namespace "f" should contain "192.168.1.0/24"
    And show command "show ip ospf route" in namespace "f" should contain "[20]"

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

  Scenario: E1 metric — external metric plus SPF cost to ASBR varies by location
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I create namespace "d"
    And I create namespace "e"
    And I create namespace "f"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I connect namespace "b" interface "ethc" to namespace "c" interface "ethb"
    And I connect namespace "c" interface "ethd" to namespace "d" interface "ethc"
    And I connect namespace "a" interface "ethd" to namespace "d" interface "etha"
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
    And I apply config "b_e1.yaml" to namespace "b"
    And I apply config "c.yaml" to namespace "c"
    And I apply config "d.yaml" to namespace "d"
    And I apply config "e.yaml" to namespace "e"
    And I apply config "f.yaml" to namespace "f"
    And I create dummy interface "cust0" with address "192.168.1.1/24" in namespace "b"
    And I wait 60 seconds

    # --- E1 metric varies by observer distance to ASBR b. ---
    # b is in area 0. a-b and c-b and d-b all cost 10, so cost-to-b = 10.
    # E1 metric from backbone routers = 10 (intra-cost) + 20 (ext-metric) = 30.
    Then show command "show ip ospf route" in namespace "a" should contain "192.168.1.0/24"
    And show command "show ip ospf route" in namespace "a" should contain "[30]"
    And show command "show ip ospf route" in namespace "c" should contain "[30]"
    And show command "show ip ospf route" in namespace "d" should contain "[30]"
    # e reaches b via a (cost 10) + Type-4 from a (a's SPF cost to b = 10) = 20.
    # E1 metric from e = 20 + 20 = 40.
    And show command "show ip ospf route" in namespace "e" should contain "192.168.1.0/24"
    And show command "show ip ospf route" in namespace "e" should contain "[40]"
    # f reaches b via c (cost 10) + Type-4 from c (c's SPF cost to b = 10) = 20.
    # E1 metric from f = 20 + 20 = 40.
    And show command "show ip ospf route" in namespace "f" should contain "192.168.1.0/24"
    And show command "show ip ospf route" in namespace "f" should contain "[40]"

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
