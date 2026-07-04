@serial
@bgp_mup_forwarding
Feature: BGP MUP End.DT46 datapath forwards real traffic (ST2 -> DSD)
  Two combined MUP UPF + interwork nodes (z1, z2) each terminate a PFCP
  session (NI `core`) and originate a Type-2 Session-Transformed (ST2) route
  whose endpoint is a host behind it (ceA behind z1, ceB behind z2), plus a
  Direct Segment Discovery (DSD) route carrying the per-VRF End.DT46 SID
  (draft-ietf-bess-mup-safi, SAFI 85). Each imports the other's DSD + ST2 and
  resolves them by Direct-segment id (MUP Extended Community), installing an
  SRv6 H.Encaps route for the remote ST2 endpoint toward the remote End.DT46
  SID, resolved through the IS-IS SRv6 underlay. So a bidirectional ceA<->ceB
  ping traverses the MUP End.DT46 datapath in BOTH directions using only
  MUP-installed routes — the forwarding counterpart of bgp_mup_st2_dsd_fib
  (which asserts the install; this drives real packets through it).

  zebra-rs uses End.DT46 as the mainline-kernel stand-in for the draft's
  GTP-U edge behaviours (GTP4.E / H.M.GTP4.D), which need a VPP/eBPF forwarder
  (see docs/design/bgp-mup-dataplane-plan.md, Plan A). Because a VRF binds a
  single MUP direction, one bidirectional subscriber path is realized by two
  collocated nodes (each an ST2 anchor for its own host), not one.

  Test Topology:
  ```
        2001:db8::1/128            2001:db8::2/128
   ceA ─┤    z1    │══ IS-IS L2 ══│    z2    ├─ ceB
 10.10.1.2  UPF+MUP-C  SRv6+iBGP   UPF+MUP-C  10.20.2.2
   /24  │ VRF N6   │   (mup)      │ VRF N6   │  /24
        └──────────┘              └──────────┘
   z1-z2 2001:db8:0:12::1/64  2001:db8:0:12::2/64
  ```

  NOTE: needs `pfcp-inject` on the BDD host PATH and root netns (kernel VRF +
  seg6 + IS-IS SRv6 underlay).

  Scenario: Build topology and establish iBGP with the MUP capability
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I create namespace "ceA"
    And I create namespace "ceB"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I connect namespace "z1" interface "ce1" to namespace "ceA" interface "eth0"
    And I connect namespace "z2" interface "ce2" to namespace "ceB" interface "eth0"
    And I add address "10.10.1.2/24" to interface "eth0" in namespace "ceA"
    And I add address "10.20.2.2/24" to interface "eth0" in namespace "ceB"
    And I add route "0.0.0.0/0" via "10.10.1.1" in namespace "ceA"
    And I add route "0.0.0.0/0" via "10.20.2.1" in namespace "ceB"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 45 seconds
    Then BGP session in "z1" to "2001:db8::2" should be "Established"
    And BGP session in "z2" to "2001:db8::1" should be "Established"

  Scenario: Each node resolves the peer ST2 to its DSD and installs the encap
    Given the test topology exists
    # z1 anchors ceA (10.10.1.2); z2 anchors ceB (10.20.2.2). Each originates
    # its ST2 (endpoint = its host) + a DSD, from a PFCP session on NI `core`.
    When I execute "pfcp-inject --target 127.0.0.1 --port 8805 --ue-ipv4 192.0.2.1 --teid 0x11 --endpoint 10.10.1.2 --core-endpoint 10.10.1.2 --core-teid 0x11 --network-instance core" in namespace "z1"
    And I execute "pfcp-inject --target 127.0.0.1 --port 8805 --ue-ipv4 192.0.2.2 --teid 0x22 --endpoint 10.20.2.2 --core-endpoint 10.20.2.2 --core-teid 0x22 --network-instance core" in namespace "z2"
    # z1 imports z2's ST2 + DSD (id 2:2) and installs the encap for ceB.
    Then show command "show bgp vrf N6 mup" in namespace "z1" should eventually contain "[ST2][65501:10][ep=10.20.2.2]"
    And show command "show bgp vrf N6 mup" in namespace "z1" should eventually contain "resolved mup:2:2 -> End.DT46"
    And command "ip route show table all" in namespace "z1" should eventually contain "encap seg6 mode encap segs 1 [ fcbb:bbbb:2:"
    And command "ip route show table all" in namespace "z1" should eventually contain "10.20.2.2"
    # z2 imports z1's ST2 + DSD (id 1:1) and installs the encap for ceA.
    And show command "show bgp vrf N6 mup" in namespace "z2" should eventually contain "[ST2][65501:20][ep=10.10.1.2]"
    And command "ip route show table all" in namespace "z2" should eventually contain "encap seg6 mode encap segs 1 [ fcbb:bbbb:1:"
    And command "ip route show table all" in namespace "z2" should eventually contain "10.10.1.2"

  Scenario: ceA <-> ceB traffic forwards over the MUP End.DT46 datapath
    Given the test topology exists
    # ceA -> ceB: z1 H.Encaps toward z2's DSD (ceB /32), z2 decaps into VRF N6.
    Then ping from "ceA" to "10.20.2.2" should eventually succeed
    # ceB -> ceA: z2 H.Encaps toward z1's DSD (ceA /32), z1 decaps into VRF N6.
    And ping from "ceB" to "10.10.1.2" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "ceA"
    And I delete namespace "ceB"
    Then the test environment should be clean
