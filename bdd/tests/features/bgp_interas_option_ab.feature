@serial
@bgp_interas_option_ab
Feature: Inter-AS MPLS/VPN Option AB over SR-MPLS (RFC 4364 hybrid)
  As a service provider running L3VPN across two autonomous systems
  I want Inter-AS Option AB: the ASBRs keep a per-VPN VRF and forward
  through it (the VPN label terminates at the ASBR → VRF lookup →
  re-impose, like Option A), but exchange every VPN over a single MP-eBGP
  VPNv4 session on one labelled link (like Option B). Each ASBR's
  `inter-as-hybrid` VRF re-exports the VPNv4 routes it imports, relaying
  the remote AS's prefixes to its own PEs.

  Test Topology (8 namespaces):
  ```
            AS 65000                                AS 65001
   ce1 ── pe1 ──── p1 ──── asbr1 ════════ asbr2 ──── p2 ──── pe2 ── ce2
          lo        lo       lo  172.16.0.0/30 lo      lo      lo
       1.1.1.1   1.1.1.2  1.1.1.3  (global)   2.2.2.3 2.2.2.2 2.2.2.1
   └ vrf-cust ┘        └ vrf-cust ┘        └ vrf-cust ┘    └ vrf-cust ┘
    10.1.0.0/30        (transit, no CE)   (transit, no CE)  10.2.0.0/30
  ```
  - Intra-AS: IS-IS L2 + segment-routing mpls; VPNv4 iBGP PE↔ASBR over
    the SR-MPLS core.
  - Inter-AS (asbr1↔asbr2, 172.16.0.0/30): a single-hop **MP-eBGP VPNv4**
    session over a link in the GLOBAL table. Each ASBR holds vrf-cust (no
    interface, no CE) with `inter-as-hybrid`, so it imports the VPNv4 it
    receives into the VRF (for per-VRF forwarding) AND re-exports it onward.
  - A CE→CE packet is VPN-labelled PE→ASBR over the SR core; at each ASBR
    the label terminates (DecapVrf → VRF lookup) and a new label is
    imposed — toward the peer ASBR (single label on the inter-AS link) or
    toward the egress PE over its SR core.

  Scenario: Build the Inter-AS Option AB topology and bring up every session
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

  Scenario: Each ASBR holds every VPN prefix in its per-VPN VRF (the "A" half)
    Given the test topology exists
    # Unlike Option B (routes in the global VPNv4 table), an Option AB ASBR
    # imports both prefixes into vrf-cust: the local-AS one from its PE, the
    # remote-AS one from the single inter-AS eBGP VPNv4 session.
    Then show command "show ip route vrf vrf-cust" in namespace "asbr1" should contain "10.1.0.0/30"
    And show command "show ip route vrf vrf-cust" in namespace "asbr1" should contain "10.2.0.0/30"
    And show command "show ip route vrf vrf-cust" in namespace "asbr2" should contain "10.1.0.0/30"
    And show command "show ip route vrf vrf-cust" in namespace "asbr2" should contain "10.2.0.0/30"

  Scenario: Each PE imports the remote-AS customer prefix into its VRF
    Given the test topology exists
    Then show command "show ip route vrf vrf-cust" in namespace "pe1" should contain "10.2.0.0/30"
    And show command "show ip route vrf vrf-cust" in namespace "pe2" should contain "10.1.0.0/30"

  Scenario: End-to-end customer forwarding across the AS boundary (per-VRF label swap)
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
