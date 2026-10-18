@serial
@bgp_vrf_vpn_evpn_same_rd
Feature: A VRF keeps a prefix imported as both VPNv4 and EVPN Type-5 under one RD
  As a network operator
  I want a VRF that imports the same prefix from one PE both as a VPNv4
  route and as an EVPN Type-5 route, under the same route distinguisher,
  to keep the prefix while either copy is still advertised.

  zebra-rs exports a VRF's routes as VPNv4 and, with `evpn
  advertise-ipv4`, also as Type-5, both under the VRF's own RD, so a PE
  that negotiates both families receives two copies of each route. The
  importing VRF used to key an imported row by its origin RD alone: the
  two copies were one row, the copy imported last overwrote the other,
  and withdrawing either copy removed the prefix from the VRF while the
  other was still advertised. Each copy is now its own candidate.

  Test Topology:
  ```
  ┌─────────────┐  VPNv4 + EVPN  ┌─────────────┐
  │     z1      │     iBGP       │     z2      │
  │  AS 65001   │───────────────▶│  AS 65001   │
  │ vrf-blue    │                │ vrf-blue    │
  │ RD 65001:100│                │ RD 65001:200│
  │ net 10.1.   │                │ (import     │
  │  0.0/24     │                │  only)      │
  └─────────────┘                └─────────────┘
   192.168.0.1                    192.168.0.2
  ```

  z1 sends 10.1.0.0/24 to z2 in both families under RD 65001:100, with
  RT 65001:100, which z2 imports into vrf-blue. An outbound DENY-ALL
  policy on one family withdraws only that family's copy (z1-no-evpn.yaml,
  z1-no-vpn.yaml); z1-none.yaml denies both.

  Scenario: Setup topology
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-both.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z2" to "192.168.0.1" should eventually be "Established"

  Scenario: z2 receives both copies and imports the prefix
    Given the test topology exists
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "10.1.0.0"
    And show command "show bgp vpnv4" in namespace "z2" should eventually contain "10.1.0.0/24"
    And show command "show bgp vrf vrf-blue" in namespace "z2" should eventually contain "10.1.0.0/24"

  Scenario: Withdrawing the Type-5 copy leaves the VPNv4 import in the VRF
    Given the test topology exists
    When I apply config "z1-no-evpn.yaml" to namespace "z1"
    Then show command "show bgp evpn" in namespace "z2" should eventually not contain "10.1.0.0"
    And show command "show bgp vpnv4" in namespace "z2" should contain "10.1.0.0/24"
    # The regression assertion: before the fix the Type-5 withdraw removed
    # the one row the two copies shared. The wait lets the VRF task drain
    # the withdraw before the check.
    When I wait 3 seconds for BGP to operate
    Then show command "show bgp vrf vrf-blue" in namespace "z2" should contain "10.1.0.0/24"

  Scenario: Both copies are imported again
    Given the test topology exists
    When I apply config "z1-both.yaml" to namespace "z1"
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "10.1.0.0"
    And show command "show bgp vpnv4" in namespace "z2" should contain "10.1.0.0/24"
    And show command "show bgp vrf vrf-blue" in namespace "z2" should eventually contain "10.1.0.0/24"

  Scenario: Withdrawing the VPNv4 copy leaves the Type-5 import in the VRF
    Given the test topology exists
    When I apply config "z1-no-vpn.yaml" to namespace "z1"
    Then show command "show bgp vpnv4" in namespace "z2" should eventually not contain "10.1.0.0/24"
    And show command "show bgp evpn" in namespace "z2" should contain "10.1.0.0"
    When I wait 3 seconds for BGP to operate
    Then show command "show bgp vrf vrf-blue" in namespace "z2" should contain "10.1.0.0/24"

  # No stale row: once neither copy is advertised the prefix leaves.
  Scenario: Withdrawing both copies empties the VRF
    Given the test topology exists
    When I apply config "z1-none.yaml" to namespace "z1"
    Then show command "show bgp evpn" in namespace "z2" should eventually not contain "10.1.0.0"
    And show command "show bgp vpnv4" in namespace "z2" should eventually not contain "10.1.0.0/24"
    And show command "show bgp vrf vrf-blue" in namespace "z2" should eventually not contain "10.1.0.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
