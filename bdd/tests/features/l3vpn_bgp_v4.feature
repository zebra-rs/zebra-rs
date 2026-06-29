@serial
@l3vpn_bgp_v4
Feature: MPLS/VPN L3VPN (IPv4) with BGP PE-CE and a customer site
  As a service provider running RFC 4364 L3VPN over SR-MPLS
  I want a full [C]-[CE]-[PE]-[P]-[PE]-[CE]-[C] topology where the
  customer edge runs eBGP to the PE and the customer site originates a
  loopback, so that C1 and C2 can reach each other's loopback across the
  MPLS/VPN core (VPNv4 over an SR-MPLS LSP through the P transit).

  Test Topology (7 namespaces):
  ```
   c1 --- ce1 --- pe1 --- p --- pe2 --- ce2 --- c2
   lo      |       lo     lo     lo      |       lo
  10.0.1.1 |    1.1.1.1 1.1.1.2 1.1.1.3  |    10.0.2.1
           |    (sid 1) (sid 2) (sid 3)  |
   AS65101 \_AS65001_/  vrf-cust  \_AS65002_/  AS65102
  ```
  - Core (pe1-p-pe2): IS-IS L2 + segment-routing mpls; loopback
    Prefix-SIDs build the PE-PE transport LSP (SRGB 16000), P is the
    transit LSR. pe1<->pe2 iBGP carries VPNv4 over loopbacks.
  - PE-CE (ce<->pe, inside vrf-cust): eBGP; CE-learned routes export to
    VPNv4 (RD 65000:1 / 65000:2, RT 65000:100).
  - C-CE (c<->ce): eBGP; C redistributes its loopback (connected) into
    BGP and CE re-advertises it to the PE.
  - The C1<->C2 loopback ping exercises C-CE eBGP + PE-CE eBGP + VPNv4
    over the SR-MPLS core.

  Scenario: Build the L3VPN topology and bring up every session
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
    And I wait 40 seconds for BGP to operate
    # IS-IS SR adjacencies form the core transport LSP.
    Then isis neighbor in namespace "pe1" at level 2 on interface "p" should be up
    And isis neighbor in namespace "pe2" at level 2 on interface "p" should be up
    And isis neighbor in namespace "p" at level 2 on interface "pe1" should be up
    And isis neighbor in namespace "p" at level 2 on interface "pe2" should be up

  Scenario: SR-MPLS transport LSPs are installed on the core P router
    Given the test topology exists
    # P is penultimate to PE1 (sid 1 -> 16001) and PE2 (sid 3 -> 16003).
    Then mpls ilm in namespace "p" should contain label 16001
    And mpls ilm in namespace "p" should contain label 16003

  Scenario: PE-PE VPNv4 and C-CE eBGP sessions are Established
    Given the test topology exists
    # pe1<->pe2 iBGP (VPNv4) over loopbacks via the SR-MPLS LSP.
    Then BGP session in "pe1" to "1.1.1.3" should be "Established"
    And BGP session in "pe2" to "1.1.1.1" should be "Established"
    # C-CE eBGP (the PE-CE session lives in vrf-cust and is proven by the
    # VPNv4 route exchange below; the `BGP session` step only queries the
    # global instance, so VRF neighbors aren't asserted here).
    And BGP session in "c1" to "10.1.0.2" should be "Established"
    And BGP session in "c2" to "10.2.0.2" should be "Established"

  Scenario: Customer loopbacks are exchanged as VPNv4 between the PEs
    Given the test topology exists
    # PE1 learns C2's loopback under PE2's RD (65000:2) and vice versa.
    Then show command "show bgp vpnv4" in namespace "pe1" should eventually contain "10.0.2.1/32"
    And show command "show bgp vpnv4" in namespace "pe2" should eventually contain "10.0.1.1/32"

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
