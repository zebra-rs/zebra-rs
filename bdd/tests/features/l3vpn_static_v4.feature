@serial
@l3vpn_static_v4
Feature: MPLS/VPN L3VPN (IPv4) with static PE-CE and a customer site
  As a service provider running RFC 4364 L3VPN over SR-MPLS
  I want a full [C]-[CE]-[PE]-[P]-[PE]-[CE]-[C] topology where the PE-CE
  and C-CE segments are statically routed and the PE redistributes the
  customer static route into VPNv4, so that C1 and C2 can reach each
  other's loopback across the MPLS/VPN core.

  Test Topology (7 namespaces) — same core as @l3vpn_bgp_v4; the customer
  side is static instead of eBGP:
  ```
   c1 --- ce1 --- pe1 --- p --- pe2 --- ce2 --- c2
   lo      |       lo     lo     lo      |       lo
  10.0.1.1 |    1.1.1.1 1.1.1.2 1.1.1.3  |    10.0.2.1
           |    (sid 1) (sid 2) (sid 3)  |
           \__ static __/ vrf-cust \__ static __/
  ```
  - Core (pe1-p-pe2): IS-IS L2 + segment-routing mpls; iBGP VPNv4.
  - PE-CE: PE holds a per-VRF static route to the customer loopback via
    the CE and `redistribute static` into VPNv4. The CE has a static
    route to the customer loopback and a default toward the PE; the
    customer has a default toward the CE. Down-direction traffic rides
    the CE/customer default routes.

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
    And I wait 40 seconds for BGP to operate
    Then isis neighbor in namespace "pe1" at level 2 on interface "p" should be up
    And isis neighbor in namespace "pe2" at level 2 on interface "p" should be up

  Scenario: SR-MPLS transport LSPs are installed on the core P router
    Given the test topology exists
    Then mpls ilm in namespace "p" should contain label 16001
    And mpls ilm in namespace "p" should contain label 16003

  Scenario: PE-PE VPNv4 session is Established and carries the customer loopbacks
    Given the test topology exists
    Then BGP session in "pe1" to "1.1.1.3" should be "Established"
    And BGP session in "pe2" to "1.1.1.1" should be "Established"
    # The redistributed static route is exported to VPNv4 across the core.
    And show command "show bgp vpnv4" in namespace "pe1" should eventually contain "10.0.2.1/32"
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
