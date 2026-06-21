@serial
@bgp_evpn_segmentation
Feature: BGP EVPN BUM tunnel segmentation — inter-region RBR (RFC 9572 Section 6)
  As a network operator
  I want a Regional Border Router to aggregate a region's per-PE Inclusive
  Multicast (Type-3) routes into a single Per-Region I-PMSI (Type-9) route,
  re-originated into the other region with next-hop-self, while not leaking
  the per-PE IMET across the region boundary.

  Test Topology — three iBGP (AS 65001) speakers on a shared bridge. z2 is the
  Regional Border Router; its neighbor-groups carry the region-id of each
  bordered region. z1 (region A) originates a Type-3 IMET; z3 (region B) only
  peers with z2.
  ```
  ┌──────────────────────────────────────────────────────────┐
  │                            br0                            │
  └─────────┬─────────────────┬─────────────────┬─────────────┘
            │                 │                 │
       ┌────┴────┐       ┌────┴────┐       ┌────┴────┐
       │   z1    │       │   z2    │       │   z3    │
       │region A │       │   RBR   │       │region B │
       │ .0.1/24 │       │ .0.2/24 │       │ .0.3/24 │
       │ VNI 10  │       │ a:65001 │       │         │
       │         │       │ b:65002 │       │         │
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
    And BGP session in "z2" to "192.168.0.3" should be "Established"

  Scenario: The RBR aggregates region A's IMET into a Per-Region I-PMSI route
    Given the test topology exists
    # z2 receives z1's per-PE IMET (region A) ...
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "[3]:[0]:[32]:[192.168.0.1]"
    # ... and re-originates a single Type-9 carrying region A's Region ID
    # (AS:65001, the Source-AS encoding of region-id 65001).
    And show command "show bgp evpn route-type per-region-imet" in namespace "z2" should eventually contain "[9]:[0]:[AS:65001]"

  Scenario: Region B receives the Per-Region I-PMSI with the RBR as next hop
    Given the test topology exists
    # z3 learns region A only through the aggregated Type-9 route, whose BGP
    # next hop is the RBR z2 (192.168.0.2).
    Then show command "show bgp evpn route-type per-region-imet" in namespace "z3" should eventually contain "[9]:[0]:[AS:65001]"
    And show command "show bgp evpn" in namespace "z3" should eventually contain "192.168.0.2"

  Scenario: Per-PE IMET is not propagated across the region boundary
    Given the test topology exists
    # The RBR holds region A's per-PE IMET at the boundary; z3 sees the
    # aggregated Type-9 instead, never z1's individual Type-3.
    Then show command "show bgp evpn" in namespace "z3" should not contain "[3]:[0]:[32]:[192.168.0.1]"

  Scenario: Region B leaf answers the Per-Region I-PMSI with a Leaf A-D
    Given the test topology exists
    # The RBR's Type-9 carries the L (Leaf Information Required) flag (RFC 9572
    # Section 6.3), so z3 originates a Leaf A-D (Type-11) keyed by that Type-9
    # NLRI (route-type 9) and reporting its own VTEP (192.168.0.3).
    Then show command "show bgp evpn route-type leaf" in namespace "z3" should eventually contain "[11]:[rt9"
    And show command "show bgp evpn route-type leaf" in namespace "z3" should eventually contain "192.168.0.3"

  Scenario: The RBR collects the region's Leaf A-D route
    Given the test topology exists
    # z3's Leaf A-D is scoped to the RBR (IP-specific RT 192.168.0.2:0) and
    # carried back to z2, letting the RBR learn region B's tunnel leaf set.
    Then show command "show bgp evpn route-type leaf" in namespace "z2" should eventually contain "[11]:[rt9"
    And show command "show bgp evpn route-type leaf" in namespace "z2" should eventually contain "192.168.0.3"

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
