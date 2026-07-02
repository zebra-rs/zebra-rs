@serial
@bgp_mup_peerdown
Feature: BGP MUP peer-down withdraws the RT-imported per-VRF copy
  As a network operator
  I want a BGP MUP route (SAFI 85 / draft-ietf-bess-mup-safi) learned from a
  peer to be withdrawn from EVERY table when that peer goes down — not just
  the main-instance MUP Loc-RIB but also every VRF that imported it by
  route-target — so a session loss cannot leak a stale route (and its derived
  SRv6 FIB entry) into a downlink VRF's RIB forever.

  Test Topology:
  ```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ MUP PE   │   iBGP (mup)    │ receiver │
       │ N6 (ISD) │                 │ N3 (imp) │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
  ```

  z1's VRF N6 (rd 65501:20, `encapsulation srv6`, `afi-safi mup segment
  interwork prefix 10.60.0.0/16`) originates an ISD carrying export RT
  65501:10 and advertises it to z2. z2's VRF N3 (rd 65501:99) imports RT
  65501:10, so it pulls the peer-learned ISD in across the RD boundary and
  re-keys it under its own rd (65501:99). When z1 is stopped, z2's peer-down
  cleanup must drop the ISD from BOTH z2's main MUP Loc-RIB (`show bgp mup`)
  and N3's imported copy (`show bgp vrf N3 mup`). Before the fix the main copy
  was dropped but N3's RT-imported copy leaked.

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
    And show command "show bgp neighbor 2001:db8::1" in namespace "z2" should contain "IPv4 MUP: advertised and received"

  Scenario: z2 receives the ISD and imports it into VRF N3 by route-target
    Given the test topology exists
    # The peer-learned ISD lands in z2's main MUP Loc-RIB under the origin RD.
    Then show command "show bgp mup" in namespace "z2" should eventually contain "[ISD][65501:20][10.60.0.0/16]"
    And show command "show bgp mup" in namespace "z2" should contain "End.DT46"
    # N3 imports it across the RD boundary by RT (65501:10) and re-keys it
    # under N3's own rd (65501:99) — RT-matched, not RD-matched.
    And show command "show bgp vrf N3 mup" in namespace "z2" should eventually contain "[ISD][65501:99][10.60.0.0/16]"
    And show command "show bgp vrf N3 mup" in namespace "z2" should contain "rt:65501:10"

  Scenario: When the peer (z1) goes down z2 withdraws the ISD from BOTH tables
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    # The main-instance MUP Loc-RIB drops the peer-learned ISD (this already
    # worked before the fix).
    Then show command "show bgp mup" in namespace "z2" should eventually not contain "10.60.0.0/16"
    # The crux: the RT-imported per-VRF copy must be withdrawn too. Before the
    # fix `route_clean` dropped the route from the main Loc-RIB only and never
    # dispatched the withdrawal to the importing VRF, so this leaked forever.
    And show command "show bgp vrf N3 mup" in namespace "z2" should eventually not contain "10.60.0.0/16"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
