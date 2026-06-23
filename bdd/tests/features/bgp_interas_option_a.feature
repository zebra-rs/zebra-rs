@serial
@bgp_interas_option_a
Feature: Inter-AS MPLS/VPN Option A over SR-MPLS (RFC 4364 §10a)
  As a service provider running L3VPN across two autonomous systems
  I want Inter-AS Option A: the ASBRs are back-to-back PEs joined by a
  per-VPN VRF interface, over which they run a PE-CE eBGP session inside
  the VRF. The VPN label terminates at each ASBR — the inter-AS link
  carries plain IP inside the VRF — and each AS runs an ordinary intra-AS
  L3VPN (PE↔ASBR VPNv4 over an SR-MPLS core).

  Test Topology (8 namespaces):
  ```
            AS 65000                              AS 65001
   ce1 ── pe1 ──── p1 ──── asbr1 ─── asbr2 ──── p2 ──── pe2 ── ce2
          lo        lo       lo  172.16  lo      lo      lo
       1.1.1.1   1.1.1.2  1.1.1.3 .0.0/30 2.2.2.3 2.2.2.2 2.2.2.1
   └ vrf-cust ┘          └ vrf ┘ (in VRF) └ vrf ┘       └ vrf-cust ┘
    10.1.0.0/30                                         10.2.0.0/30
  ```
  - Intra-AS: IS-IS L2 + segment-routing mpls; VPNv4 iBGP PE↔ASBR over
    the SR-MPLS core (the PE loopback next-hop is resolved by the IGP —
    no BGP-LU). ASBR1 and PE1 are both PEs of AS 65000; likewise AS 65001.
  - Inter-AS (asbr1↔asbr2, 172.16.0.0/30): the link is in `vrf-cust` on
    both ASBRs (NOT in the IGP). They run a **PE-CE eBGP session inside
    vrf-cust**. Routes learned there are re-exported to VPNv4; imported
    VPNv4 routes are advertised over it. Plain IP on the wire.
  - A CE→CE packet is VPN-labeled PE→ASBR, decapsulated to plain IP at
    the ASBR, forwarded over the inter-AS VRF link, then re-labeled
    ASBR→PE in the far AS.

  Scenario: Build the Inter-AS Option A topology and bring up every session
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
    # 75s, not the 35s the sibling option features use: the customer
    # prefix crosses the longest chain here — CE2 → PE2 (VPNv4) → ASBR2
    # → (PE-CE eBGP) → ASBR1 → re-export to VPNv4 → PE1 → import — so end-
    # to-end convergence (measured ~55-60s) needs the extra headroom.
    And I wait 75 seconds for BGP to operate
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

  Scenario: SR-MPLS transport LSPs are installed on the core P routers
    Given the test topology exists
    Then mpls ilm in namespace "p1" should contain label 16001
    And mpls ilm in namespace "p1" should contain label 16003
    And mpls ilm in namespace "p2" should contain label 16004
    And mpls ilm in namespace "p2" should contain label 16006

  Scenario: The customer prefixes cross the AS boundary via the per-VRF PE-CE eBGP
    Given the test topology exists
    # ASBR1's vrf-cust holds PE1's prefix (from intra-AS VPNv4) AND CE2's
    # prefix (learned from ASBR2 over the inter-AS PE-CE eBGP, AS-path 65001).
    Then show command "show ip route vrf vrf-cust" in namespace "asbr1" should contain "10.1.0.0/30"
    And show command "show ip route vrf vrf-cust" in namespace "asbr1" should contain "10.2.0.0/30"
    And show command "show ip route vrf vrf-cust" in namespace "asbr2" should contain "10.1.0.0/30"
    And show command "show ip route vrf vrf-cust" in namespace "asbr2" should contain "10.2.0.0/30"

  Scenario: Each PE imports the remote-AS customer prefix into its VRF
    Given the test topology exists
    Then show command "show ip route vrf vrf-cust" in namespace "pe1" should contain "10.2.0.0/30"
    And show command "show ip route vrf vrf-cust" in namespace "pe2" should contain "10.1.0.0/30"

  Scenario: End-to-end customer forwarding across the AS boundary (VPN + back-to-back VRF)
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
