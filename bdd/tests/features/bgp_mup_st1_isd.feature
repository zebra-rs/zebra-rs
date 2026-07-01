@serial
@bgp_mup_st1_isd
Feature: BGP MUP ST1 resolves to a remote ISD segment and installs SRv6 encap
  An interwork / UPF node imports a remote Interwork Segment Discovery (ISD,
  type 1, SAFI 85 / draft-ietf-bess-mup-safi) route — whose prefix is the gNB
  N3 network — and — via its MUP controller — originates a Type-1
  Session-Transformed (ST1) route whose GTP endpoint (gNB) address falls
  inside that prefix. Because the endpoint is covered by the (remote) ISD,
  the node resolves the ST1 to the ISD's End.DT46 segment and installs an
  SRv6 H.Encaps route for the endpoint into the VRF table, resolved through
  the IS-IS SRv6 underlay toward the ISD's next-hop.

  Test Topology:
  ```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ access PE│   iBGP (mup)    │ UPF +    │
       │  (ISD)   │                 │ MUP-C    │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
  ```

  z1 (VRF N6, rd 65501:10, `segment interwork prefix 10.0.0.0/24`, export RT
  65501:10) originates the ISD (End.DT46 SID from locator S). z2 (VRF N6, rd
  65501:20, `encapsulation srv6`, import RT 65501:10) imports the ISD and,
  from a PFCP session on NI `access`, originates an ST1 (UE 10.60.1.5, gNB
  endpoint 10.0.0.1 inside 10.0.0.0/24). z2 resolves the ST1's endpoint to
  z1's segment and installs the endpoint encap.

  NOTE: needs `pfcp-inject` on the BDD host PATH and root netns (kernel VRF +
  seg6 + IS-IS SRv6 underlay).

  Scenario: Build topology and establish iBGP with the MUP capability
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 45 seconds
    Then BGP session in "z1" to "2001:db8::2" should be "Established"
    And BGP session in "z2" to "2001:db8::1" should be "Established"
    # z2 imports z1's ISD (re-keyed under its own rd 65501:20).
    And show command "show bgp vrf N6 mup" in namespace "z2" should eventually contain "[ISD][65501:20][10.0.0.0/24]"

  Scenario: z2 resolves the ST1 to z1's ISD segment and installs the encap
    Given the test topology exists
    When I execute "pfcp-inject --target 127.0.0.1 --port 8805 --ue-ipv4 10.60.1.5 --teid 0x12345678 --endpoint 10.0.0.1 --network-instance access" in namespace "z2"
    # The ST1's gNB endpoint (10.0.0.1) is covered by the ISD 10.0.0.0/24, so
    # the per-VRF view shows the resolution to the ISD's End.DT46 segment.
    Then show command "show bgp vrf N6 mup" in namespace "z2" should eventually contain "resolved 10.0.0.1 -> End.DT46"
    # The SRv6 H.Encaps route for the endpoint is installed into the VRF
    # table, resolved through the underlay toward z1's End.DT46 SID (locator S
    # = fcbb:bbbb:1::/48).
    And command "ip route show table all" in namespace "z2" should eventually contain "encap seg6 mode encap segs 1 [ fcbb:bbbb:1:"
    And command "ip route show table all" in namespace "z2" should eventually contain "10.0.0.1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
