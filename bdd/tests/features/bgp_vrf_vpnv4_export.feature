@serial
@bgp_vrf_vpnv4_export
Feature: BGP per-VRF VPNv4 export to a remote PE
  As a network operator
  I want to advertise a network configured under `router bgp vrf X
  afi-safi ipv4` as a VPNv4 NLRI toward a remote PE
  Using a two-namespace topology where z1 originates the prefix
  inside vrf-blue and z2 peers with z1 over VPNv4 only.

  Test Topology:
  ```
  ┌─────────────┐                ┌─────────────┐
  │     z1      │   VPNv4 iBGP   │     z2      │
  │  AS 65001   │ ◀────────────▶ │  AS 65001   │
  │ vrf-blue:   │                │ vrf-blue:   │
  │  RD 65001:  │                │  RD 65001:  │
  │   100       │                │   200       │
  │  RT 65001:  │                │  RT 65001:  │
  │   100 imp/  │                │   100 imp/  │
  │   exp       │                │   exp       │
  │  net 10.1.  │                │             │
  │   0.0/24    │                │             │
  └─────────────┘                └─────────────┘
   192.168.0.1                    192.168.0.2
  ```

  Config files:
  - z1-1.yaml: AS 65001, vrf-blue with RD 65001:100, RT 65001:100,
    and a self-originated network 10.1.0.0/24. VPNv4 iBGP to z2.
  - z2-1.yaml: AS 65001, vrf-blue with RD 65001:200, RT 65001:100
    (matching import). VPNv4 iBGP to z1.

  Scenario: Setup topology
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: z1 advertises the self-originated network as VPNv4
    Given the test topology exists
    Then show command "show bgp vpnv4" in namespace "z1" should contain "10.1.0.0/24"
    And show command "show bgp vpnv4" in namespace "z1" should contain "65001:100"

  Scenario: z2 receives the VPNv4 NLRI under the same RD
    Given the test topology exists
    Then show command "show bgp vpnv4" in namespace "z2" should contain "10.1.0.0/24"
    And show command "show bgp vpnv4" in namespace "z2" should contain "65001:100"

  Scenario: VPNv4 route detail by address and by exact prefix
    Given the test topology exists
    Then show command "show bgp vpnv4 10.1.0.1" in namespace "z2" should contain "BGP routing table entry for 10.1.0.0/24"
    And show command "show bgp vpnv4 10.1.0.0/24" in namespace "z2" should contain "Route Distinguisher: 65001:100"

  Scenario: Deleting the VRF withdraws its VPNv4 exports from the remote PE
    Given the test topology exists
    # z1-2.yaml is z1-1.yaml minus `router bgp vrf vrf-blue` — the BGP
    # VRF despawn path. The exported row must leave both the local
    # VPNv4 Loc-RIB and the remote PE; a stale advertisement here plus
    # the immediately-reused service label would decap remote traffic
    # into the wrong VRF.
    When I apply config "z1-2.yaml" to namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then show command "show bgp vpnv4" in namespace "z1" should not contain "10.1.0.0/24"
    And show command "show bgp vpnv4" in namespace "z2" should not contain "10.1.0.0/24"

  Scenario: Re-adding the VRF re-exports the network
    Given the test topology exists
    When I apply config "z1-1.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp vpnv4" in namespace "z2" should contain "10.1.0.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
