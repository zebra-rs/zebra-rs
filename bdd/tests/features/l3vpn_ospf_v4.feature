@serial
@l3vpn_ospf_v4
Feature: MPLS/VPN L3VPN (IPv4) with OSPFv2 PE-CE both segments
  As a service provider running RFC 4364 L3VPN over SR-MPLS
  I want a full [C]-[CE]-[PE]-[P]-[PE]-[CE]-[C] topology where both the
  C-CE and PE-CE segments run OSPFv2 and the PE does two-way
  redistribution (OSPF<->VPNv4), so that C1 and C2 can reach each other's
  loopback across the MPLS/VPN core.

  Same core as @l3vpn_bgp_v4 (IS-IS L2 + SR-MPLS, iBGP VPNv4). The
  customer side runs OSPFv2 in area 0 (C-CE and CE-PE). The PE:
  - `router bgp vrf ... redistribute ospf` carries the customer routes
    OSPF learned from the CE up into VPNv4 (up direction);
  - `router ospf vrf ... redistribute bgp` injects the VPNv4 routes
    imported into the VRF back into the CE-facing OSPF as Type-5
    AS-External LSAs (down direction — the feature added for this).

  Scenario: Build the L3VPN topology and bring up the core
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "ce1"
    And I create namespace "pe1"
    And I create namespace "p"
    And I create namespace "pe2"
    And I create namespace "ce2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "ce1" to namespace "ce1" interface "c1"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I connect namespace "pe1" interface "p" to namespace "p" interface "pe1"
    And I connect namespace "p" interface "pe2" to namespace "pe2" interface "p"
    And I connect namespace "pe2" interface "ce2" to namespace "ce2" interface "pe2"
    And I connect namespace "ce2" interface "c2" to namespace "c2" interface "ce2"
    And I start zebra-rs in namespace "c1"
    And I start zebra-rs in namespace "ce1"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "p"
    And I start zebra-rs in namespace "pe2"
    And I start zebra-rs in namespace "ce2"
    And I start zebra-rs in namespace "c2"
    And I apply config "c1.yaml" to namespace "c1"
    And I apply config "ce1.yaml" to namespace "ce1"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "p.yaml" to namespace "p"
    And I apply config "pe2.yaml" to namespace "pe2"
    And I apply config "ce2.yaml" to namespace "ce2"
    And I apply config "c2.yaml" to namespace "c2"
    And I wait 60 seconds for BGP to operate
    Then isis neighbor in namespace "pe1" at level 2 on interface "p" should be up
    And isis neighbor in namespace "pe2" at level 2 on interface "p" should be up

  Scenario: Customer routes are carried as VPNv4 (OSPF -> BGP, up direction)
    Given the test topology exists
    Then BGP session in "pe1" to "1.1.1.3" should be "Established"
    And BGP session in "pe2" to "1.1.1.1" should be "Established"
    And show command "show bgp vpnv4" in namespace "pe1" should eventually contain "10.0.2.1/32"
    And show command "show bgp vpnv4" in namespace "pe2" should eventually contain "10.0.1.1/32"

  Scenario: Remote customer loopbacks reach the customer site (BGP -> OSPF, down direction)
    Given the test topology exists
    # PE1 injects the VPNv4-imported C2 loopback into the CE-facing OSPF;
    # C1 learns it as an OSPF AS-External route.
    Then show command "show ip route" in namespace "c1" should eventually contain "10.0.2.1"
    And show command "show ip route" in namespace "c2" should eventually contain "10.0.1.1"

  Scenario: End-to-end customer loopback reachability across the MPLS/VPN core
    Given the test topology exists
    Then ping from "c1" to "10.0.2.1" should eventually succeed
    And ping from "c2" to "10.0.1.1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "c1"
    And I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "p"
    And I stop zebra-rs in namespace "pe2"
    And I stop zebra-rs in namespace "ce2"
    And I stop zebra-rs in namespace "c2"
    And I delete namespace "c1"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    And I delete namespace "p"
    And I delete namespace "pe2"
    And I delete namespace "ce2"
    And I delete namespace "c2"
    Then the test environment should be clean
