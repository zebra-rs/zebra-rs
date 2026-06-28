@serial
@bgp_vrf_redistribute
Feature: BGP per-VRF redistribute connected/static to VPNv4
  As a network operator
  I want `router bgp vrf X afi-safi ipv4 redistribute {connected,static}`
  to pull a VRF's connected and static routes into the per-VRF BGP table
  and export them to VPNv4 toward a remote PE — the IOS-XR L3VPN model,
  without a CE-facing routing protocol.

  Test Topology:
  ```
   h1(10.1.0.2) ── z1[vrf-blue]  ── VPNv4 iBGP ──  z2[vrf-blue]
                   vc1 10.1.0.1/24                  RD 65001:200
                   static 10.2.0.0/24               RT 65001:100 import
                   RD 65001:100, RT 65001:100
                   redistribute connected + static
   192.168.0.1 ───────────── br0 ───────────── 192.168.0.2
  ```

  Config files:
  - z1-1.yaml: AS 65001, vrf-blue (RD 65001:100, RT 65001:100), vc1 in
    the VRF with 10.1.0.1/24 (connected 10.1.0.0/24), a VRF static route
    10.2.0.0/24 via 10.1.0.2, and `afi-safi ipv4 redistribute
    {connected,static}`. VPNv4 iBGP to z2.
  - z2-1.yaml: AS 65001, vrf-blue (RD 65001:200, RT 65001:100 import).
    VPNv4 iBGP to z1.

  Scenario: Setup topology
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "h1"
    And I connect namespace "z1" interface "vc1" to namespace "h1" interface "eth0"
    And I add address "10.1.0.2/24" to interface "eth0" in namespace "h1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: The VRF connected route lands in the VRF table (Phase 0 prereq)
    Given the test topology exists
    Then show command "show ip route vrf vrf-blue" in namespace "z1" should contain "10.1.0.0/24"
    And show command "show ip route vrf vrf-blue" in namespace "z1" should contain "10.2.0.0/24"

  Scenario: z1 redistributes the VRF connected + static routes as VPNv4
    Given the test topology exists
    Then show command "show bgp vpnv4" in namespace "z1" should contain "10.1.0.0/24"
    And show command "show bgp vpnv4" in namespace "z1" should contain "10.2.0.0/24"
    And show command "show bgp vpnv4" in namespace "z1" should contain "65001:100"

  Scenario: z2 receives the redistributed VRF prefixes as VPNv4 under z1's RD
    Given the test topology exists
    Then show command "show bgp vpnv4" in namespace "z2" should contain "10.1.0.0/24"
    And show command "show bgp vpnv4" in namespace "z2" should contain "10.2.0.0/24"
    And show command "show bgp vpnv4 10.1.0.0/24" in namespace "z2" should contain "Route Distinguisher: 65001:100"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "h1"
    And I delete bridge "br0"
    Then the test environment should be clean
