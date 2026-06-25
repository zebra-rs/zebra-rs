@serial
@bgp_mup_isd
Feature: BGP MUP PE originates an Interwork Segment Discovery (ISD) route over SRv6
  As a network operator
  I want a zebra-rs BGP MUP PE to originate an Interwork Segment Discovery
  (ISD, type 1, SAFI 85 / RFC 9833) route for an `encapsulation srv6` VRF
  when `afi-safi mup segment interwork prefix <p>` is configured, so the
  per-VRF End.DT46 service SID is carved from the locator, installed into the
  kernel FIB, and advertised under the configured interwork prefix as the
  segment a receiving PE resolves for matching Session-Transformed routes.

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

  z1 has VRF N6 (`encapsulation srv6`, rd 65501:10) and `afi-safi mup
  segment interwork prefix 10.60.0.0/16`, so it carves an End.DT46 SID from
  locator S, installs the seg6local decap into N6's table, and originates an
  ISD route (NLRI = rd + the interwork prefix 10.60.0.0/16) carrying that
  SID. z2 receives it.

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

  Scenario: z1 originates the ISD route and installs the End.DT46 SID
    Given the test topology exists
    # The ISD NLRI is the VRF RD + the configured interwork prefix; an IPv4
    # prefix rides the IPv4-MUP AFI.
    Then show command "show bgp mup" in namespace "z1" should eventually contain "[ISD][65501:10][10.60.0.0/16]"
    # The route carries the per-VRF End.DT46 SID as a local SRv6 L3 Service.
    And show command "show bgp mup" in namespace "z1" should contain "Local SID"
    And show command "show bgp mup" in namespace "z1" should contain "End.DT46"
    # The ISD carries the VRF's export route-target (no MUP Extended Community
    # — the interwork route is resolved by endpoint-address lookup, §3.1.1).
    And show command "show bgp mup" in namespace "z1" should contain "rt:65501:10"
    # The per-VRF view mirrors the originated ISD (its RD matches N6's rd).
    And show command "show bgp vrf N6 mup" in namespace "z1" should eventually contain "[ISD][65501:10][10.60.0.0/16]"
    # The End.DT46 decap is installed into the kernel FIB.
    And command "ip -6 route show table all" in namespace "z1" should eventually contain "End.DT46"

  Scenario: z2 receives the ISD route with the End.DT46 SID
    Given the test topology exists
    Then show command "show bgp mup" in namespace "z2" should eventually contain "[ISD][65501:10][10.60.0.0/16]"
    And show command "show bgp mup" in namespace "z2" should contain "Remote SID"
    And show command "show bgp mup" in namespace "z2" should contain "End.DT46"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
