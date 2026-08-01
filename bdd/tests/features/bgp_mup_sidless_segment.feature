@serial
@bgp_mup_sidless_segment
Feature: A GTP-only MUP PE originates SID-less Segment Discovery routes
  As a network operator running a GTP-only UPF (dataplane gtp, no SRv6)
  I want `segment direct` / `segment interwork` to still advertise the
  DSD / ISD routes — without an SRv6 L3 Service Prefix-SID — so a peer can
  correlate Session-Transformed routes to my segments by Direct-segment id
  and prefix containment (stage 6 of
  docs/design/bgp-mup-gtp-segment-resolution-plan.md). The controller
  address serves as the next-hop (there is no locator to derive one from).

  Test Topology:
  ```
        2001:db8::1 (lo)                2001:db8::2 (lo)
       ┌──────────────┐     iBGP (mup)  ┌──────────┐
       │      z1      │═════════════════│    z2    │
       │ GTP-only UPF │  over the link  │ receiver │
       │ vrf N3 + N6  │                 │          │
       └──────────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64       2001:db8:0:12::2/64
  ```

  z1 has NO segment-routing locator and neither VRF uses `encapsulation
  srv6`; both declare `dataplane gtp`. N6 (`segment direct { mup-ext-comm
  1:6 }`, rd 65501:20) originates a SID-less DSD; N3 (`segment interwork {
  prefix 10.0.1.0/24 }`, rd 65501:10) a SID-less ISD.

  Scenario: Build topology and establish iBGP with the MUP capability
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 15 seconds
    Then BGP session in "z1" to "2001:db8:0:12::2" should be "Established"
    And BGP session in "z2" to "2001:db8:0:12::1" should be "Established"
    And show command "show bgp neighbor 2001:db8:0:12::2" in namespace "z1" should contain "IPv4 MUP: advertised and received"

  Scenario: z1 originates both segments without a Prefix-SID
    Given the test topology exists
    Then show command "show bgp mup" in namespace "z1" should eventually contain "[DSD][65501:20][10.0.0.1]"
    And show command "show bgp mup" in namespace "z1" should eventually contain "[ISD][65501:10][10.0.1.0/24]"
    # The Direct-segment id rides the DSD as usual.
    And show command "show bgp mup" in namespace "z1" should contain "mup:1:6"
    # SID-less: no SRv6 L3 Service on either segment; the controller
    # address is the next-hop.
    And show command "show bgp mup" in namespace "z1" should not contain "Local SID"
    And show command "show bgp mup" in namespace "z1" should not contain "End.DT46"
    And show command "show bgp mup" in namespace "z1" should contain "next-hop 2001:db8::1"

  Scenario: z2 receives both SID-less segments
    Given the test topology exists
    Then show command "show bgp mup" in namespace "z2" should eventually contain "[DSD][65501:20][10.0.0.1]"
    And show command "show bgp mup" in namespace "z2" should eventually contain "[ISD][65501:10][10.0.1.0/24]"
    And show command "show bgp mup" in namespace "z2" should contain "mup:1:6"
    And show command "show bgp mup" in namespace "z2" should not contain "Remote SID"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
