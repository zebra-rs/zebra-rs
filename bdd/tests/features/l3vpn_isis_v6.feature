@serial
@l3vpn_isis_v6
Feature: SRv6 L3VPN (IPv6) with IS-IS PE-CE both segments
  As a service provider running L3VPN over SRv6 (zebra-rs has no 6VPE)
  I want a full [C]-[CE]-[PE]-[P]-[PE]-[CE]-[C] topology where both the
  C-CE and PE-CE segments run IS-IS (IPv6) and the PE does two-way
  redistribution (IS-IS<->VPNv6 over SRv6 End.DT46), so that C1 and C2
  can reach each other's IPv6 loopback across the SRv6 core.

  The PE runs the global IS-IS SRv6 core plus a per-VRF IS-IS (IPv6) to
  the CE. Up: `router bgp vrf ... redistribute isis` -> VPNv6. Down:
  `router isis vrf ... afi-safi ipv6 redistribute bgp` -> the VPNv6
  routes imported into the VRF are injected into the CE-facing IS-IS.

  Scenario: Build the SRv6 L3VPN topology and bring up the core
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

  Scenario: Customer routes are carried as VPNv6 (IS-IS -> BGP, up direction)
    Given the test topology exists
    Then BGP session in "pe1" to "2001:db8::3" should be "Established"
    And BGP session in "pe2" to "2001:db8::1" should be "Established"
    And show command "show bgp vpnv6" in namespace "pe1" should eventually contain "2001:db8:c2::1/128"
    And show command "show bgp vpnv6" in namespace "pe2" should eventually contain "2001:db8:c1::1/128"

  Scenario: End-to-end customer loopback reachability across the SRv6 core
    Given the test topology exists
    Then ping from "c1" to "2001:db8:c2::1" should eventually succeed
    And ping from "c2" to "2001:db8:c1::1" should eventually succeed

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
