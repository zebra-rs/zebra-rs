@serial
@bgp_evpn_mpls
Feature: EVPN over MPLS advertises a per-EVI service label (RFC 7432)
  As a network operator running EVPN's L2 services over an MPLS core
  I want each PE to advertise its EVI with an MPLS service label and to
  program the matching decap, so a remote PE knows what to impose on frames
  toward this one — the control plane behind the eBPF data path that
  forwards it.

  Test topology (control plane only — no CEs, no bridges, no forwarding):
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65001 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
   encapsulation mpls, evi 100 bridge br100 on both
  ```

  What distinguishes MPLS from the VXLAN and SRv6 encapsulations, and what
  this feature pins:

  - The EVI is *declared*, not inferred. VXLAN and SRv6 read a local VXLAN
    device's VNI; an MPLS EVI has no VNI, so `evi 100 bridge br100` is what
    tells the PE this L2 service exists at all.
  - The Type-3 IMET carries an MPLS **label** in its PMSI, not a VNI, and
    the label is a different number from the EVI id (it comes from the
    dynamic block, so it is deliberately NOT asserted as a literal).
  - The next hop and PMSI tunnel identifier are the router-id, not a VTEP.
  - No Encapsulation extended community is attached: RFC 8365 section 5.1.3
    makes MPLS the default and signals it by that EC's *absence*, so its
    presence would be the bug.
  - A decap ILM is programmed at the service label so a remote PE's frame
    pops into bridge domain 100. It is cradle-only — the kernel has no
    action that pops a label into a bridge — so `show mpls ilm` is the only
    place it is observable without a data plane.

  Type-2 (MAC/IP) needs a datapath MAC learn and is covered by the
  cradle-rs `cradle_evpn_mpls_zebra` feature, which drives this same control
  plane with a real eBPF data plane and CE-to-CE traffic.

  Scenario: Setup topology and establish the EVPN session
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: Each PE originates a Type-3 IMET for its declared EVI
    Given the test topology exists
    # RD is <router-id>:<evi> and the next hop is the router-id — there is no
    # VTEP address in an MPLS EVPN.
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "192.168.0.1:100"
    And show command "show bgp evpn" in namespace "z1" should eventually contain "[3]:[0]:[32]:[192.168.0.1]"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "[3]:[0]:[32]:[192.168.0.2]"

  Scenario: The IMET reaches the far PE with an MPLS label, not a VNI
    Given the test topology exists
    # `label:` (rather than `vni:`) is what the show path renders for a path
    # with no Encapsulation EC — the MPLS signal itself.
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "[3]:[0]:[32]:[192.168.0.1]"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "ingress-replication endpoint:192.168.0.1 label:"
    And show command "show bgp evpn" in namespace "z1" should eventually contain "ingress-replication endpoint:192.168.0.2 label:"

  Scenario: The route target carries the EVI and no encapsulation EC is set
    Given the test topology exists
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "RT:65001:100"
    # RFC 8365 5.1.3: MPLS is signalled by omitting the Encapsulation EC.
    And show command "show bgp evpn" in namespace "z2" should not contain "VXLAN"

  Scenario: Each PE programs a bridge-domain decap ILM for its EVI
    Given the test topology exists
    # Cradle-only by construction (the kernel has no MPLS-to-bridge action),
    # so this is the RIB's view rather than the kernel LFIB's.
    Then show command "show mpls ilm" in namespace "z1" should eventually contain "EVPN Decap (bd 100"
    And show command "show mpls ilm" in namespace "z2" should eventually contain "EVPN Decap (bd 100"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
