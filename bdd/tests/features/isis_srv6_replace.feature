@isis_srv6_replace
@isis
Feature: IS-IS advertises REPLACE-C-SID SRv6 endpoint behaviors
  As a network operator
  I want a locator's RFC 9800 REPLACE-C-SID format reflected in the
  advertised endpoint-behavior codepoints and SID structure, so SR
  source nodes can compress segment lists with 32-bit C-SIDs and the
  data planes agree on the wire format.

  z1's locator carries `behavior: replace` and `flavor: [psp, usd]`:
  its End SID must advertise as `End (REP, PSP, USD)` (IANA codepoint
  129, End with REPLACE-CSID, PSP & USD) and its End.X SID as
  `End.X (REP, PSP)` (106) — adjacency SIDs fold only the PSP bit.
  The advertised structure is LB 48 / LN 16 / Fun 16 / Arg 48 — the
  non-zero argument length is how receivers infer 32-bit compression
  (RFC 9800 §6.4). z2 is a plain uSID locator and must keep
  advertising `uN`/`uA`, and the adjacency and SPF must be unaffected
  by the REPLACE codepoints.

  Test Topology:
  ```
   z1 ──2001:db8:0:12::/64── z2
   LOC1 fcbb:bbbb:1:1::/64    LOC2 fcbb:bbbb:2::/48
   replace + psp,usd          usid (no flavor)
  ```

  Scenario: The REPLACE-C-SID codepoints appear in the peer's database
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then show command "show isis database detail" in namespace "z2" should eventually contain "End (REP, PSP, USD)"
    And show command "show isis database detail" in namespace "z2" should contain "End.X (REP, PSP)"
    # The uSID peer's own SIDs are unchanged — z1 sees plain uN.
    And show command "show isis database detail" in namespace "z1" should eventually contain "Behavior: uN,"
    # Reachability across the adjacency proves the REPLACE codepoints
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
