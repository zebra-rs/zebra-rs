@serial
@bgp_evpn_df_election
Feature: BGP EVPN BUM segmentation — inter-AS DF election (RFC 9572 Section 5.3.1)
  As a network operator
  I want the ASBRs that border a downstream AS to attach a DF Election Extended
  Community (RFC 8584, AC-DF cleared) to their re-originated Per-Region I-PMSI
  (Type-9) routes and elect a single Designated Forwarder, so a downstream AS
  containing legacy PEs receives no duplicated BUM traffic.

  Test Topology — region A (AS 65001) is bordered by TWO ASBRs, z2 (.0.2) and
  z4 (.0.4), both re-originating region A's Type-9 toward the downstream AS
  65002 (z3). z1 is a plain (legacy, non-segmentation) PE in region A.
  ```
  ┌──────────────────────────────────────────────────────────────────┐
  │                               br0                                 │
  └───────┬───────────────┬───────────────┬───────────────┬──────────┘
          │               │               │               │
     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
     │   z1    │iBGP │   z2    │eBGP │   z3    │eBGP │   z4    │
     │ AS65001 │─────│ ASBR #1 │─────│ AS65002 │─────│ ASBR #2 │
     │ PE,VNI10│     │  .0.2   │     │  .0.3   │     │  .0.4   │
     │  .0.1   │     │ (DF)    │     │         │     │         │
     └─────────┘     └─────────┘     └─────────┘     └─────────┘
        └────────────────iBGP──────────────────────────┘
  ```

  Scenario: Setup topology and establish the EVPN sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.0.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I apply config "z3-1.yaml" to namespace "z3"
    And I apply config "z4-1.yaml" to namespace "z4"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z3" to "192.168.0.2" should be "Established"
    And BGP session in "z3" to "192.168.0.4" should be "Established"

  Scenario: Both ASBRs attach a DF Election EC to their Per-Region I-PMSI
    Given the test topology exists
    # z3 receives region A's Type-9 from both ASBRs, each carrying the DF
    # Election EC (RFC 8584) with the default modulus algorithm.
    Then show command "show bgp evpn route-type per-region-imet" in namespace "z3" should eventually contain "[9]:[0]:[AS:65001]"
    And show command "show bgp evpn" in namespace "z3" should eventually contain "df-election:alg0"

  Scenario: The downstream AS elects the lowest-address ASBR as DF
    Given the test topology exists
    # Modulus DF election over the two candidate ASBRs (.0.2 and .0.4) with
    # Ethernet Tag 0 elects the numerically lowest, 192.168.0.2.
    Then show command "show bgp evpn" in namespace "z3" should eventually contain "DF=192.168.0.2"
    And show command "show bgp evpn" in namespace "z3" should eventually contain "candidates: 192.168.0.2 192.168.0.4"

  Scenario: An ASBR flags the legacy (non-segmentation) PE in its region
    Given the test topology exists
    # z2 receives z1's IMET, which carries no segmentation-support bit, so the
    # ASBR marks the region's VNI as having a legacy PE present.
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "legacy PEs present"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "z4"
    And I delete bridge "br0"
    Then the test environment should be clean
