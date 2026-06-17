@serial
@bgp_interas_option_c
Feature: Inter-AS MPLS/VPN Option C over SR-MPLS (RFC 4364 §10c)
  As a service provider running L3VPN across two autonomous systems
  I want Inter-AS Option C: the ASBRs exchange only labeled IPv4 (BGP-LU)
  for the PE loopbacks and hold no VPN state, while the PEs run a direct
  multihop MP-eBGP VPNv4 session whose next-hop (the remote PE loopback)
  is resolved across the AS boundary through the BGP-LU LSP, with SR-MPLS
  providing the intra-AS transport.

  This mirrors Cisco's "Configuration and Verification of L3 MPLS VPN
  Inter-AS Option C" (doc 200523), streamlined to one PE + one P + one
  ASBR per AS and a direct PE↔PE VPNv4 session (no route reflector — the
  originating PE's next-hop-self is already the correct egress, so no
  next-hop-unchanged is needed; the ASBR→PE iBGP-LU leg uses next-hop-self
  instead).

  Test Topology (8 namespaces):
  ```
            AS 65000                              AS 65001
   ce1 --- pe1 --- p1 --- asbr1 ===== asbr2 --- p2 --- pe2 --- ce2
  10.1.0.2 lo       lo     lo   172.16  lo       lo     lo   10.2.0.2
        1.1.1.1 1.1.1.2 1.1.1.3 .0.0/30 2.2.2.3 2.2.2.2 2.2.2.1
        (sid 1) (sid 2) (sid 3)         (sid 6) (sid 5) (sid 4)
   \__vrf-cust_/                                       \_vrf-cust__/
     10.1.0.0/30                                         10.2.0.0/30
  ```
  - Intra-AS: IS-IS L2 + segment-routing mpls; loopback Prefix-SIDs give
    the transport LSP (SRGB base 16000 → labels 16001..16006). P routers
    perform the real SR transit swap / PHP.
  - Inter-AS (asbr1↔asbr2, 172.16.0.0/30): eBGP labeled-unicast only —
    PE loopback /32s exchanged with labels, no IGP, no VPN state.
  - ASBR↔PE (intra-AS): iBGP labeled-unicast with next-hop-self, so the
    PE resolves the ASBR (via IS-IS) and pushes the ASBR's swap label.
  - PE↔PE: multihop eBGP VPNv4 between loopbacks. The session itself
    rides the BGP-LU LSP, so "Established" already proves end-to-end
    labeled forwarding works before any data packet is sent.
  - The CE↔CE ping exercises the full label stack: SR transport (outer)
    + BGP-LU (AS crossing) + VPN (innermost).

  Scenario: Build the Inter-AS Option C topology and bring up every session
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
    # IS-IS SR adjacencies form the intra-AS transport (polls up to 30s).
    Then isis neighbor in namespace "pe1" at level 2 on interface "p1" should be up
    And isis neighbor in namespace "asbr1" at level 2 on interface "p1" should be up
    And isis neighbor in namespace "pe2" at level 2 on interface "p2" should be up
    And isis neighbor in namespace "asbr2" at level 2 on interface "p2" should be up
    # eBGP labeled-unicast across the inter-AS link.
    And BGP session in "asbr1" to "172.16.0.2" should be "Established"
    And BGP session in "asbr2" to "172.16.0.1" should be "Established"
    # iBGP labeled-unicast ASBR↔PE inside each AS.
    And BGP session in "pe1" to "1.1.1.3" should be "Established"
    And BGP session in "pe2" to "2.2.2.3" should be "Established"
    # Multihop eBGP VPNv4 PE↔PE — riding the BGP-LU LSP. Establishing it
    # already proves labeled forwarding across the AS boundary works.
    And BGP session in "pe1" to "2.2.2.1" should be "Established"
    And BGP session in "pe2" to "1.1.1.1" should be "Established"

  Scenario: SR-MPLS transport LSPs are installed on the core P routers
    Given the test topology exists
    # P1 is penultimate to PE1 (sid 1 → 16001) and ASBR1 (sid 3 → 16003).
    Then mpls ilm in namespace "p1" should contain label 16001
    And mpls ilm in namespace "p1" should contain label 16003
    # P2 is penultimate to PE2 (sid 4 → 16004) and ASBR2 (sid 6 → 16006).
    And mpls ilm in namespace "p2" should contain label 16004
    And mpls ilm in namespace "p2" should contain label 16006

  Scenario: ASBRs exchange PE loopbacks via BGP labeled-unicast, holding no VPN state
    Given the test topology exists
    # ASBR1 originates nothing itself; it relays the local-AS PE loopback
    # (1.1.1.1/32, from PE1) and the remote-AS PE loopback (2.2.2.1/32,
    # from ASBR2) — both as labeled IPv4, no VPNv4.
    Then show command "show bgp labeled-unicast" in namespace "asbr1" should contain "1.1.1.1/32"
    And show command "show bgp labeled-unicast" in namespace "asbr1" should contain "2.2.2.1/32"
    And show command "show bgp labeled-unicast" in namespace "asbr2" should contain "1.1.1.1/32"
    And show command "show bgp labeled-unicast" in namespace "asbr2" should contain "2.2.2.1/32"

  Scenario: Each PE learns the remote PE loopback through the BGP-LU chain
    Given the test topology exists
    Then show command "show bgp labeled-unicast" in namespace "pe1" should contain "2.2.2.1/32"
    And show command "show bgp labeled-unicast" in namespace "pe2" should contain "1.1.1.1/32"

  Scenario: VPNv4 customer routes are exchanged directly between the PEs
    Given the test topology exists
    # PE1 receives PE2's customer prefix under PE2's RD (65001:1).
    Then show command "show bgp vpnv4" in namespace "pe1" should contain "10.2.0.0/30"
    And show command "show bgp vpnv4" in namespace "pe1" should contain "65001:1"
    # PE2 receives PE1's customer prefix under PE1's RD (65000:1).
    And show command "show bgp vpnv4" in namespace "pe2" should contain "10.1.0.0/30"
    And show command "show bgp vpnv4" in namespace "pe2" should contain "65000:1"

  Scenario: End-to-end customer forwarding across the AS boundary (SR + BGP-LU + VPN)
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
