@serial
@l3vpn_bgp_v6
Feature: SRv6 L3VPN (IPv6) with BGP PE-CE and a customer site
  As a service provider running L3VPN over SRv6 (zebra-rs has no 6VPE, so
  IPv6 customer VPN traffic rides SRv6 End.DT46 rather than MPLS)
  I want a full [C]-[CE]-[PE]-[P]-[PE]-[CE]-[C] topology where the
  customer edge runs IPv6 eBGP to the PE and the customer site originates
  an IPv6 loopback, so that C1 and C2 can reach each other's loopback
  across the SRv6 VPNv6 core.

  Test Topology (7 namespaces):
  ```
   c1 --- ce1 --- pe1 --- p --- pe2 --- ce2 --- c2
   lo      |       lo     lo     lo      |       lo
  c1::1    |    db8::1  db8::2 db8::3    |     c2::1
           |   LOC1 fcbb:bbbb:1::/48     |
           |        LOC2 fcbb:bbbb:2::/48|
   AS65101 \_AS65001_/  vrf-cust  \_AS65002_/  AS65102
  ```
  - Core (pe1-p-pe2): IS-IS L2 SRv6; PE loopbacks + locators are reached
    natively over IPv6 through the P transit. pe1<->pe2 iBGP carries
    VPNv6 over v6 loopbacks; the per-VRF End.DT46 SID (from each PE's
    locator) is the service SID.
  - PE-CE (ce<->pe, inside vrf-cust, encapsulation srv6): IPv6 eBGP;
    CE-learned routes export to VPNv6. Exercises the per-VRF neighbor
    `afi-safi ipv6 enabled` knob.
  - C-CE (c<->ce): IPv6 eBGP; C redistributes its loopback (connected)
    into BGP and CE re-advertises it to the PE.
  - The C1<->C2 IPv6 loopback ping exercises C-CE eBGP + PE-CE eBGP +
    VPNv6 over the SRv6 core (z2 H.Encaps toward z1's End.DT46, z1 decaps).

  Scenario: Build the SRv6 L3VPN topology and bring up every session
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
    And I wait 45 seconds
    # IS-IS SRv6 adjacencies form the v6 core.
    Then isis neighbor in namespace "pe1" at level 2 on interface "p" should be up
    And isis neighbor in namespace "pe2" at level 2 on interface "p" should be up
    And isis neighbor in namespace "p" at level 2 on interface "pe1" should be up
    And isis neighbor in namespace "p" at level 2 on interface "pe2" should be up

  Scenario: PE-PE VPNv6 and C-CE eBGP sessions are Established
    Given the test topology exists
    # pe1<->pe2 iBGP (VPNv6) over v6 loopbacks.
    Then BGP session in "pe1" to "2001:db8::3" should be "Established"
    And BGP session in "pe2" to "2001:db8::1" should be "Established"
    # C-CE IPv6 eBGP (the PE-CE session lives in vrf-cust and is proven by
    # the VPNv6 route exchange below).
    And BGP session in "c1" to "2001:db8:1c::2" should be "Established"
    And BGP session in "c2" to "2001:db8:2c::2" should be "Established"

  Scenario: Customer loopbacks are exchanged as VPNv6 between the PEs
    Given the test topology exists
    Then show command "show bgp vpnv6" in namespace "pe1" should eventually contain "2001:db8:c2::1/128"
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
