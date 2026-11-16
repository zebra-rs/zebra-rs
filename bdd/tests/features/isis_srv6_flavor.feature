@isis_srv6_flavor
@isis
Feature: IS-IS advertises PSP-flavored SRv6 endpoint behaviors
  As a network operator
  I want a locator's configured RFC 8986 §4.16 flavors folded into the
  advertised endpoint-behavior codepoints, so receivers know the SRH
  will be popped at this node and the data planes agree on the wire
  format.

  z1's uSID locator carries `flavor: [psp]`: its End SID must advertise
  as `uN (PSP)` (IANA codepoint 44, End with NEXT-CSID & PSP) and its
  End.X SID as `uA (PSP)` (53) — adjacency SIDs fold only the PSP bit.
  z2 is flavorless and must (a) keep advertising plain `uN`/`uA` and
  (b) still classify z1's flavored codepoints as NEXT-C-SID, so the
  adjacency and SPF are unaffected.

  Test Topology:
  ```
   z1 ──2001:db8:0:12::/64── z2
   LOC1 fcbb:bbbb:1::/48      LOC2 fcbb:bbbb:2::/48
   usid + flavor [psp]        usid (no flavor)
  ```

  Scenario: The flavored codepoints appear in the peer's database
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then show command "show isis database detail" in namespace "z2" should eventually contain "uN (PSP)"
    # uN rides z1's very first LSP, but uA is the End.X *adjacency* SID —
    # it only exists once the adjacency reaches Up and z1 re-originates.
    # So this must poll too; a bare `should contain` here raced the
    # re-origination and read the seq-1 LSP (see the c=8 failure 2026-07-21).
    And show command "show isis database detail" in namespace "z2" should eventually contain "uA (PSP)"
    # The flavorless peer's own SIDs are unchanged — z1 sees plain uN.
    And show command "show isis database detail" in namespace "z1" should eventually contain "Behavior: uN,"
    # Reachability across the adjacency proves the flavored codepoints
    # didn't disturb SPF or the SRv6 locator routes.
    And ping from "z1" to "2001:db8::2" should eventually succeed
    And ping from "z2" to "2001:db8::1" should eventually succeed

  Scenario: The show commands print the flavor of the local SIDs
    Given the test topology exists
    # z1's own SIDs print with PSP in the route table, the IS-IS local
    # SID table and the SID registry. The kernel performs PSP on uN but
    # not on an adjacency SID, which the route line says.
    Then show command "show ipv6 route" in namespace "z1" should eventually contain "seg6local uN (PSP)"
    And show command "show ipv6 route" in namespace "z1" should eventually contain "seg6local uA (PSP) [kernel: uA]"
    And show command "show isis route" in namespace "z1" should contain "seg6local uN (PSP)"
    And show command "show isis route" in namespace "z1" should contain "seg6local uA (PSP)"
    And show command "show segment-routing srv6 sid" in namespace "z1" should contain "uN (PSP)"
    # The flavorless peer prints the bare behaviors.
    And show command "show isis route" in namespace "z2" should contain "seg6local uN"
    And show command "show segment-routing srv6 sid" in namespace "z2" should not contain "(PSP)"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
