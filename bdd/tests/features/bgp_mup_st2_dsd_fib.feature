@serial
@bgp_mup_st2_dsd_fib
Feature: BGP MUP interwork node installs the ST2->DSD SRv6 encap
  An interwork (SRGW) node imports a Type-2 Session-Transformed (ST2) route
  and a Direct Segment Discovery (DSD) route (SAFI 85 /
  draft-ietf-bess-mup-safi) into a *forwarding* VRF, resolves each ST2 to the
  matching DSD by their Direct-segment id (MUP Extended Community), and — the
  DSD being remote — installs an SRv6 H.Encaps route for the ST2 endpoint
  into the VRF table, resolved through the IS-IS SRv6 underlay toward the
  DSD's next-hop. This is the forwarding counterpart of the show-only
  interwork resolution.

  Test Topology:
  ```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ UPF +    │   iBGP (mup)    │ interwork│
       │ MUP-C    │                 │ (SRGW,   │
       │ (DSD+ST2)│                 │  VRF N6) │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
  ```

  z1 (VRF N6, rd 65501:10, `segment direct` + `route st2`, export RT
  65501:10) originates a DSD (End.DT46 SID from locator S + id 1:2) and, from
  a PFCP session on NI `core`, an ST2 (endpoint 10.0.0.1, id 1:2). z2 (VRF
  N6, rd 65501:20, `encapsulation srv6`, import RT 65501:10) imports both,
  resolves the ST2 to z1's Direct segment, and installs the endpoint encap.

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

  Scenario: z2 resolves the ST2 to z1's Direct segment and installs the encap
    Given the test topology exists
    When I execute "pfcp-inject --target 127.0.0.1 --port 8805 --ue-ipv4 192.0.2.5 --teid 0x12345678 --endpoint 10.0.0.1 --network-instance core" in namespace "z1"
    # z2 imports the ST2 + DSD into VRF N6 (re-keyed under its own rd) and
    # resolves the ST2 to the DSD's End.DT46 segment by the id 1:2.
    Then show command "show bgp vrf N6 mup" in namespace "z2" should eventually contain "[ST2][65501:20][ep=10.0.0.1]"
    And show command "show bgp vrf N6 mup" in namespace "z2" should eventually contain "resolved mup:1:2 -> End.DT46"
    # The SRv6 H.Encaps route for the ST2 endpoint is installed into the VRF
    # table, resolved through the underlay toward z1's End.DT46 SID (locator
    # S = fcbb:bbbb:1::/48).
    And command "ip route show table all" in namespace "z2" should eventually contain "encap seg6 mode encap segs 1 [ fcbb:bbbb:1:"
    # ... for the ST2 endpoint (10.0.0.1), which is only routed by that encap.
    And command "ip route show table all" in namespace "z2" should eventually contain "10.0.0.1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
