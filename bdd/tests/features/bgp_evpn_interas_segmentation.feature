@serial
@bgp_evpn_interas_segmentation
Feature: BGP EVPN BUM tunnel segmentation — inter-AS ASBR (RFC 9572 Section 5)
  As a network operator
  I want an Autonomous System Border Router to aggregate its AS's per-PE
  Inclusive Multicast (Type-3) routes into a single Per-Region I-PMSI (Type-9)
  route, re-originated across the AS boundary (eBGP) with next-hop-self, while
  not leaking the per-AS per-PE IMET across that boundary.

  This reuses the region-id segmentation machinery with "region = AS": the
  ASBR's neighbor-groups carry a region-id equal to each bordered AS, so the
  inter-AS (Section 5) case is the inter-region (Section 6) case applied across
  an eBGP session. It exercises the eBGP egress path the all-iBGP Section 6
  test never touched — AS_PATH prepend and next-hop-self at the AS boundary.

  Test Topology — z1 (AS 65001 PE) and z2 (AS 65001 ASBR) are iBGP; z2 and z3
  (AS 65002 ASBR) are eBGP across the AS boundary.
  ```
  ┌──────────────────────────────────────────────────────────┐
  │                            br0                            │
  └─────────┬─────────────────┬─────────────────┬─────────────┘
            │                 │                 │
       ┌────┴────┐       ┌────┴────┐       ┌────┴────┐
       │   z1    │ iBGP  │   z2    │ eBGP  │   z3    │
       │ AS65001 │───────│  ASBR   │───────│ AS65002 │
       │ .0.1/24 │       │ .0.2/24 │       │ .0.3/24 │
       │ VNI 10  │       │a:65001  │       │         │
       │         │       │b:65002  │       │         │
       └─────────┘       └─────────┘       └─────────┘
  ```

  Scenario: Setup topology and establish the EVPN sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I apply config "z3-1.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    # The z2-z3 session is eBGP (AS 65001 <-> AS 65002).
    And BGP session in "z2" to "192.168.0.3" should be "Established"

  Scenario: The ASBR aggregates AS 65001's IMET into a Per-Region I-PMSI route
    Given the test topology exists
    # z2 receives z1's per-PE IMET (AS 65001) ...
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "[3]:[0]:[32]:[192.168.0.1]"
    # ... and re-originates a single Type-9 carrying AS 65001's Region ID
    # (AS:65001, the Source-AS encoding of region-id 65001).
    And show command "show bgp evpn route-type per-region-imet" in namespace "z2" should eventually contain "[9]:[0]:[AS:65001]"

  Scenario: AS 65002 receives the Per-Region I-PMSI across the eBGP boundary
    Given the test topology exists
    # z3 learns AS 65001 only through the aggregated Type-9 route, whose BGP
    # next hop is the ASBR z2 (192.168.0.2, next-hop-self at the AS boundary).
    Then show command "show bgp evpn route-type per-region-imet" in namespace "z3" should eventually contain "[9]:[0]:[AS:65001]"
    And show command "show bgp evpn" in namespace "z3" should eventually contain "192.168.0.2"

  Scenario: Per-AS per-PE IMET is not propagated across the AS boundary
    Given the test topology exists
    # The ASBR holds AS 65001's per-PE IMET at the boundary; z3 sees the
    # aggregated Type-9 instead, never z1's individual Type-3.
    Then show command "show bgp evpn" in namespace "z3" should not contain "[3]:[0]:[32]:[192.168.0.1]"

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
