@serial
@bgp_mup_srgw_gtp
Feature: A dataplane-gtp SRGW steers via remote SRv6 MUP segments
  The N9/SRGW composite (stage 6 of
  docs/design/bgp-mup-gtp-segment-resolution-plan.md): a `dataplane gtp`
  VRF whose segments are REMOTE composes GTP with SRv6 instead of ignoring
  them. Downlink: an ST1 whose gNB endpoint is covered by a received ISD
  (with a usable End.DT46 SID and resolved transport) steers the UE prefix
  via SRv6 H.Encaps toward that interwork segment — the segment owner
  performs the GTP conversion. Uplink: an ST2 whose Direct-segment id
  resolves to a received DSD gets default v4+v6 H.Encaps routes in the
  VRF's table, so GTP-decapped traffic rides SRv6 to the anchor. Local
  segments always win (this node converts / holds the table itself).

  Test Topology:
  ```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ ISD(ACC) │   iBGP (mup)    │ SRGW     │
       │ DSD(ANC) │                 │ gtp VRF  │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
  ```

  z1 owns BOTH remote segments: VRF ACC (rd 65501:10, `segment interwork
  prefix 10.0.0.0/24`, export RT 65501:10) and VRF ANC (rd 65501:30,
  `segment direct { mup-ext-comm 1:2 }`, export RT 65501:30), each with an
  End.DT46 SID from locator S. z2's VRF mobile (rd 65501:20, `dataplane
  gtp`, NO srv6 encapsulation) imports both and originates — from one PFCP
  session on NI `access` — an ST1 (UE 10.60.1.5, gNB 10.0.0.1 inside the
  ISD prefix) and an ST2 stamped `mup:1:2`.

  NOTE: needs `pfcp-inject` on the BDD host PATH and root netns (kernel
  VRF + seg6 + IS-IS SRv6 underlay).

  Scenario: Build topology and import both remote segments
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
    And show command "show bgp vrf mobile mup" in namespace "z2" should eventually contain "[ISD][65501:20][10.0.0.0/24]"
    And show command "show bgp vrf mobile mup" in namespace "z2" should eventually contain "[DSD][65501:20]"

  Scenario: One session drives both composites — SRv6 downlink steer and uplink default
    Given the test topology exists
    When I execute "pfcp-inject --target 127.0.0.1 --port 8805 --ue-ipv4 10.60.1.5 --teid 0x12345678 --endpoint 10.0.0.1 --n3-endpoint 10.0.99.2 --n3-teid 0x500 --network-instance access" in namespace "z2"
    # Downlink composite: the ST1's gNB endpoint (10.0.0.1) is covered by
    # the REMOTE ISD, so the UE prefix steers via SRv6 toward z1's segment
    # (locator S = fcbb:bbbb:1::/48) instead of local GTP encap.
    Then show command "show bgp vrf mobile mup" in namespace "z2" should eventually contain "resolved 10.60.1.5/32 (endpoint 10.0.0.1) -> End.DT46"
    And command "ip route show table all" in namespace "z2" should eventually contain "10.60.1.5"
    And command "ip route show table all" in namespace "z2" should eventually contain "encap seg6 mode encap segs 1 [ fcbb:bbbb:1:"
    # Uplink composite: the ST2's Direct-segment id (mup:1:2) resolves to
    # the REMOTE DSD — default v4+v6 H.Encaps routes appear in the VRF
    # table, steering decapped traffic to the anchor.
    And command "ip route show table all" in namespace "z2" should eventually contain "default"
    And command "ip -6 route show table all" in namespace "z2" should eventually contain "default"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
