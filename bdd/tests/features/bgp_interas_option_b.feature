@serial
@bgp_interas_option_b
Feature: Inter-AS MPLS/VPN Option B over SR-MPLS (RFC 4364 §10b)
  As a service provider running L3VPN across two autonomous systems
  I want Inter-AS Option B: the ASBRs exchange VPNv4 routes directly over
  a single-hop MP-eBGP session and re-advertise them with next-hop-self,
  allocating a fresh local label and a swap ILM for each, so the VPN
  crosses the AS boundary as a label switch — the ASBRs hold every VPN
  route but no VRF, and the inter-AS link carries labelled VPNv4 packets.

  Test Topology (8 namespaces):
  ```
            AS 65000                                AS 65001
   ce1 ── pe1 ──── p1 ──── asbr1 ════════ asbr2 ──── p2 ──── pe2 ── ce2
          lo        lo       lo  172.16.0.0/30 lo      lo      lo
       1.1.1.1   1.1.1.2  1.1.1.3  (global)   2.2.2.3 2.2.2.2 2.2.2.1
   └ vrf-cust ┘                                            └ vrf-cust ┘
    10.1.0.0/30                                            10.2.0.0/30
  ```
  - Intra-AS: IS-IS L2 + segment-routing mpls; VPNv4 iBGP PE↔ASBR over
    the SR-MPLS core (the PE loopback next-hop is resolved by the IGP —
    no BGP-LU).
  - Inter-AS (asbr1↔asbr2, 172.16.0.0/30): a single-hop **MP-eBGP VPNv4**
    session over a link in the GLOBAL table (NOT the IGP). The ASBRs run
    NO VRF: a received VPNv4 route sits in the global v4vpn RIB and is
    re-advertised with next-hop-self, a freshly allocated local label and
    a swap ILM (our label → received label, toward the original next-hop).
  - A CE→CE packet is VPN-labelled PE→ASBR over the SR core; the ASBR
    swaps the VPN label and forwards a single labelled packet across the
    inter-AS link; the far ASBR swaps again over its SR core to the egress
    PE, which pops and delivers plain IP to the CE.

  Scenario: Build the Inter-AS Option B topology and bring up every session
    Given a clean test environment
    When I create namespace "ce1"
    And I create namespace "pe1"
    And I create namespace "p1"
    And I create namespace "asbr1"
    And I create namespace "asbr2"
    And I create namespace "p2"
    And I create namespace "pe2"
    And I create namespace "ce2"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I connect namespace "pe1" interface "p1" to namespace "p1" interface "pe1"
    And I connect namespace "p1" interface "asbr1" to namespace "asbr1" interface "p1"
    And I connect namespace "asbr1" interface "asbr2" to namespace "asbr2" interface "asbr1"
    And I connect namespace "asbr2" interface "p2" to namespace "p2" interface "asbr2"
    And I connect namespace "p2" interface "pe2" to namespace "pe2" interface "p2"
    And I connect namespace "pe2" interface "ce2" to namespace "ce2" interface "pe2"
    And I start zebra-rs in namespace "ce1"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "p1"
    And I start zebra-rs in namespace "asbr1"
    And I start zebra-rs in namespace "asbr2"
    And I start zebra-rs in namespace "p2"
    And I start zebra-rs in namespace "pe2"
    And I start zebra-rs in namespace "ce2"
    And I apply config "ce1.yaml" to namespace "ce1"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "p1.yaml" to namespace "p1"
    And I apply config "asbr1.yaml" to namespace "asbr1"
    And I apply config "asbr2.yaml" to namespace "asbr2"
    And I apply config "p2.yaml" to namespace "p2"
    And I apply config "pe2.yaml" to namespace "pe2"
    And I apply config "ce2.yaml" to namespace "ce2"
    And I wait 35 seconds for BGP to operate
    # IS-IS SR adjacencies form the intra-AS transport.
    Then isis neighbor in namespace "pe1" at level 2 on interface "p1" should be up
    And isis neighbor in namespace "asbr1" at level 2 on interface "p1" should be up
    And isis neighbor in namespace "pe2" at level 2 on interface "p2" should be up
    And isis neighbor in namespace "asbr2" at level 2 on interface "p2" should be up
    # Intra-AS VPNv4 iBGP PE↔ASBR in each AS.
    And BGP session in "pe1" to "1.1.1.3" should be "Established"
    And BGP session in "asbr1" to "1.1.1.1" should be "Established"
    And BGP session in "pe2" to "2.2.2.3" should be "Established"
    And BGP session in "asbr2" to "2.2.2.1" should be "Established"
    # Inter-AS single-hop MP-eBGP VPNv4 between the ASBRs.
    And BGP session in "asbr1" to "172.16.0.2" should be "Established"
    And BGP session in "asbr2" to "172.16.0.1" should be "Established"

  Scenario: SR-MPLS transport LSPs are installed on the core P routers
    Given the test topology exists
    Then mpls ilm in namespace "p1" should contain label 16001
    And mpls ilm in namespace "p1" should contain label 16003
    And mpls ilm in namespace "p2" should contain label 16004
    And mpls ilm in namespace "p2" should contain label 16006

  Scenario: The ASBRs hold every VPN prefix in the global VPNv4 table (no VRF)
    Given the test topology exists
    # ASBR1 learns 10.1.0.0/30 from PE1 (intra-AS VPNv4) and 10.2.0.0/30
    # from ASBR2 (inter-AS eBGP VPNv4); ASBR2 mirrors. Neither runs a VRF.
    Then show command "show bgp vpnv4" in namespace "asbr1" should contain "10.1.0.0/30"
    And show command "show bgp vpnv4" in namespace "asbr1" should contain "10.2.0.0/30"
    And show command "show bgp vpnv4" in namespace "asbr2" should contain "10.1.0.0/30"
    And show command "show bgp vpnv4" in namespace "asbr2" should contain "10.2.0.0/30"

  Scenario: Each PE imports the remote-AS customer prefix into its VRF
    Given the test topology exists
    Then show command "show ip route vrf vrf-cust" in namespace "pe1" should contain "10.2.0.0/30"
    And show command "show ip route vrf vrf-cust" in namespace "pe2" should contain "10.1.0.0/30"

  Scenario: End-to-end customer forwarding across the AS boundary (VPNv4 label swap)
    Given the test topology exists
    Then ping from "ce1" to "10.2.0.2" should succeed
    And ping from "ce2" to "10.1.0.2" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "p1"
    And I stop zebra-rs in namespace "asbr1"
    And I stop zebra-rs in namespace "asbr2"
    And I stop zebra-rs in namespace "p2"
    And I stop zebra-rs in namespace "pe2"
    And I stop zebra-rs in namespace "ce2"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    And I delete namespace "p1"
    And I delete namespace "asbr1"
    And I delete namespace "asbr2"
    And I delete namespace "p2"
    And I delete namespace "pe2"
    And I delete namespace "ce2"
    Then the test environment should be clean
