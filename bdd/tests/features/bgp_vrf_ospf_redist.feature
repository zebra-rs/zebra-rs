@serial
@bgp_vrf_ospf_redist
Feature: BGP per-VRF redistribute OSPF to VPNv4
  As a network operator
  I want `router bgp vrf X afi-safi ipv4 redistribute ospf` to pull a
  VRF's OSPF-learned routes (installed by a per-VRF OSPF instance into
  the VRF table) into the per-VRF BGP table and export them to VPNv4 —
  so a PE advertises CE-learned IGP routes into the L3VPN.

  Test Topology:
  ```
   ce(OSPF) ── oc1 ── z1[vrf-blue: ospf + bgp] ── VPNv4 iBGP ── z2[vrf-blue]
   lo 10.9.9.9/32     10.0.0.1/30 (vrf-blue)                    RD 65001:200
   area 0             router ospf vrf vrf-blue                  RT 65001:100 imp
                      redistribute ospf, RD 65001:100
   10.0.0.2/30 ───────────── (veth) ──────────
   192.168.0.1 ───────────── br0 ───────────── 192.168.0.2
  ```

  Config files:
  - ce.yaml: OSPF only; lo 10.9.9.9/32 + eth0 10.0.0.2/30 in area 0.
  - z1-1.yaml: vrf-blue (RD 65001:100, RT 65001:100), oc1 in the VRF
    (10.0.0.1/30), `router ospf vrf vrf-blue` on oc1, `afi-safi ipv4
    redistribute ospf`, VPNv4 iBGP to z2.
  - z2-1.yaml: vrf-blue (RD 65001:200, RT 65001:100 import), VPNv4 iBGP
    to z1.

  Scenario: Setup topology
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "ce"
    And I connect namespace "z1" interface "oc1" to namespace "ce" interface "eth0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "ce"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I apply config "ce.yaml" to namespace "ce"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: z1 learns the CE's OSPF route in the VRF table
    Given the test topology exists
    Then show command "show ip route vrf vrf-blue" in namespace "z1" should eventually contain "10.9.9.9/32"

  Scenario: z1 redistributes the VRF OSPF route as VPNv4, not the connected link
    Given the test topology exists
    Then show command "show bgp vpnv4" in namespace "z1" should eventually contain "10.9.9.9/32"
    And show command "show bgp vpnv4" in namespace "z1" should eventually contain "65001:100"
    # `redistribute ospf` takes only OSPF routes — the connected /30 link
    # is RibType::Connected, so it must NOT be exported.
    And show command "show bgp vpnv4" in namespace "z1" should not contain "10.0.0.0/30"

  Scenario: z2 receives the redistributed OSPF prefix as VPNv4 under z1's RD
    Given the test topology exists
    Then show command "show bgp vpnv4" in namespace "z2" should eventually contain "10.9.9.9/32"
    And show command "show bgp vpnv4 10.9.9.9/32" in namespace "z2" should eventually contain "Route Distinguisher: 65001:100"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "ce"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "ce"
    And I delete bridge "br0"
    Then the test environment should be clean
