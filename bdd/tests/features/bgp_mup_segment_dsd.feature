@serial
@bgp_mup_segment_dsd
Feature: BGP MUP PE originates a Direct Segment Discovery (DSD) route over SRv6
  As a network operator
  I want a zebra-rs BGP MUP PE to originate a Direct Segment Discovery
  (DSD, type 2, SAFI 85 / RFC 9833) route for an `encapsulation srv6` VRF
  when `afi-safi mup segment direct` is configured, so the per-VRF End.DT46
  service SID is carved from the locator, installed into the kernel FIB, and
  advertised as the segment a receiving PE resolves for matching
  Session-Transformed routes (the draft-ietf-bess-mup-safi default).

  Test Topology:
  ```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ MUP PE   │   iBGP (mup)    │ receiver │
       │ vrf N6   │                 │          │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
  ```

  z1 has VRF N6 (`encapsulation srv6`, rd 65501:10) and
  `afi-safi mup segment direct`, so it carves an End.DT46 SID from locator
  S, installs the seg6local decap into N6's table, and originates a DSD
  route (NLRI = rd + router-id 10.0.0.1) carrying that SID. z2 receives it.

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
    And show command "show bgp neighbor 2001:db8::2" in namespace "z1" should contain "IPv4 MUP: advertised and received"

  Scenario: z1 originates the DSD route and installs the End.DT46 SID
    Given the test topology exists
    # The DSD NLRI is the VRF RD + router-id, riding the IPv4-MUP AFI.
    Then show command "show bgp mup" in namespace "z1" should eventually contain "[DSD][65501:10][10.0.0.1]"
    # The route carries the per-VRF End.DT46 SID as a local SRv6 L3 Service.
    And show command "show bgp mup" in namespace "z1" should contain "Local SID"
    And show command "show bgp mup" in namespace "z1" should contain "End.DT46"
    # The DSD advertises its BGP MUP Extended Community (Direct segment ID,
    # `mup-ext-comm 1:2`), rendered bare in the RD/RT 2:4 form alongside the
    # export route-target.
    And show command "show bgp mup" in namespace "z1" should contain "rt:65501:10 mup:1:2"
    # The per-VRF view mirrors the originated DSD (its RD matches N6's rd).
    And show command "show bgp vrf N6 mup" in namespace "z1" should eventually contain "[DSD][65501:10][10.0.0.1]"
    # Step 4: the End.DT46 decap is installed into the kernel FIB.
    And command "ip -6 route show table all" in namespace "z1" should eventually contain "End.DT46"

  Scenario: z2 receives the DSD route with the End.DT46 SID
    Given the test topology exists
    Then show command "show bgp mup" in namespace "z2" should eventually contain "[DSD][65501:10][10.0.0.1]"
    And show command "show bgp mup" in namespace "z2" should contain "Remote SID"
    And show command "show bgp mup" in namespace "z2" should contain "End.DT46"
    # The Direct segment ID (MUP Extended Community) rides through to the peer.
    And show command "show bgp mup" in namespace "z2" should contain "rt:65501:10 mup:1:2"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
