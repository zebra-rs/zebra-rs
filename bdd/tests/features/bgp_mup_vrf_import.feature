@serial
@bgp_mup_vrf_import
Feature: BGP MUP cross-VRF import by route-target (RD-independent)
  As a network operator
  I want a locally-originated BGP MUP route (SAFI 85 / RFC 9833) to be
  imported into every VRF whose `mup route-target import` overlaps the
  route's RTs — not just the VRF that owns the route's RD — so per-VRF MUP
  matches the VPNv4/v6 import model and a downlink VRF can pull in the
  upstream segment another VRF originated.

  Test Topology:
  ```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ MUP PE   │   iBGP (mup)    │ receiver │
       │ N6 + N3  │                 │          │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
  ```

  On z1, VRF N6 (rd 65501:20, `encapsulation srv6`, `afi-safi mup segment
  interwork prefix 10.60.0.0/16`) originates an ISD route carrying its export
  RT 65501:10. VRF N3 (rd 65501:10) imports RT 65501:10, so it pulls in N6's
  ISD even though the ISD's RD (65501:20) does not equal N3's own rd — the
  proof that per-VRF MUP import is route-target matched, not RD matched.

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

  Scenario: z1 originates the ISD in N6 and installs the End.DT46 SID
    Given the test topology exists
    # The ISD NLRI is N6's RD (65501:20) + the configured interwork prefix.
    Then show command "show bgp mup" in namespace "z1" should eventually contain "[ISD][65501:20][10.60.0.0/16]"
    And show command "show bgp mup" in namespace "z1" should contain "End.DT46"
    # The ISD carries N6's export route-target.
    And show command "show bgp mup" in namespace "z1" should contain "rt:65501:10"
    # The End.DT46 decap is installed into the kernel FIB.
    And command "ip -6 route show table all" in namespace "z1" should eventually contain "End.DT46"

  Scenario: N6 self-imports its own ISD (rd 65501:20 imports rt 65501:10)
    Given the test topology exists
    Then show command "show bgp vrf N6 mup" in namespace "z1" should eventually contain "[ISD][65501:20][10.60.0.0/16]"
    And show command "show bgp vrf N6 mup" in namespace "z1" should contain "End.DT46"

  Scenario: N3 imports N6's ISD across the RD boundary by route-target
    Given the test topology exists
    # The crux: N3's own rd is 65501:10, but the ISD's RD is 65501:20. It
    # appears here only because N3 imports RT 65501:10, which the ISD carries
    # — RT-matched import, not RD-matched.
    Then show command "show bgp vrf N3 mup" in namespace "z1" should eventually contain "[ISD][65501:20][10.60.0.0/16]"
    And show command "show bgp vrf N3 mup" in namespace "z1" should contain "End.DT46"
    And show command "show bgp vrf N3 mup" in namespace "z1" should contain "rt:65501:10"

  Scenario: z2 receives the ISD route with the End.DT46 SID
    Given the test topology exists
    Then show command "show bgp mup" in namespace "z2" should eventually contain "[ISD][65501:20][10.60.0.0/16]"
    And show command "show bgp mup" in namespace "z2" should contain "Remote SID"
    And show command "show bgp mup" in namespace "z2" should contain "End.DT46"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
