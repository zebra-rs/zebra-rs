@isis_srv6_endt
@isis
Feature: IS-IS advertises End.T / uT for VRF-bound SRv6 locators
  As a network operator
  I want a locator bound to a VRF (`vrf` leaf) to advertise its node
  SID as End.T — or uT for a uSID locator — so receivers know the End
  walk's egress lookup happens in the bound table (RFC 8986 §4.3).

  z1's classic locator carries `vrf: vrf-one` and `flavor: [psp]`: its
  End SID must advertise as `End.T (PSP)` (IANA codepoint 10). z2's
  uSID locator carries `vrf: vrf-two`: its node SID advertises as `uT`
  (End.T with NEXT-CSID, codepoint 85). The adjacency SIDs stay
  End.X/uA, and SPF/reachability must be unaffected.

  Test Topology:
  ```
   z1 ──2001:db8:0:12::/64── z2
   LOC1 fcbb:bbbb:1::/48      LOC2 fcbb:bbbb:2::/48
   classic + vrf-one + psp    usid + vrf-two
  ```

  Scenario: The table-scoped codepoints appear in the peer's database
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then show command "show isis database detail" in namespace "z2" should eventually contain "End.T (PSP)"
    And show command "show isis database detail" in namespace "z1" should eventually contain "Behavior: uT,"
    # Reachability across the adjacency proves the End.T codepoints
    # didn't disturb SPF or the locator routes.
    And ping from "z1" to "2001:db8::2" should eventually succeed
    And ping from "z2" to "2001:db8::1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
