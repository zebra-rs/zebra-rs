@classic_tilfa_v3
Feature: OSPFv3 TI-LFA fast-reroute over SRv6 classic (full) SIDs
  As a network operator
  I want eight zebra-rs instances running OSPFv3 with classic
  (RFC 8986 full-SID) SRv6 locators and TI-LFA (RFC 9490) to
  pre-compute a topology-independent repair as an SRv6 SID list, so
  that when the primary link fails the source still reaches the
  destination.

  This is the classic-SID sibling of `ospfv3_tilfa_srv6.feature`
  (same RFC 9855 §5 topology and costs). The only configuration
  difference is the locator: `behavior usid` is omitted, so SIDs use
  the classic RFC 8986 full-SID layout. Observable consequences this
  feature pins:
  - `show segment-routing srv6 sid` lists `End` / `End.X` — never the
    micro-SID `uN` / `uA` forms, and no `uA(LIB)` twin rows;
  - the repair SID list does NOT compress: each segment is a full
    128-bit SID, so the inserted SRH for the protected route to d is
    [End(r1), End.X(r1-r2), End.X(r2-r3)] + the original destination
    = 4 segments, where the uSID sibling carries 2;
  - everything else is unchanged: H.Insert encap, neighbor-global
    End.X nexthops, and the promoted-backup forwarding proof.

  Test Topology (cost shown where != 1; loopback 2001:db8::X /
  locator fcbb:bbbb:X::/48 classic / router-id 10.0.0.X):
  ```
                 s (2001:db8::1)
             1 / 1 \      \ 1000
              n1    n2     n3
          1 / |1 \1  \1     \1000
       d ─┘ 1 |   \    \      \
 (2001:db8::8)│    \1000\      \
          1 \ │     r1───────── (r1-n3 1000)
             r3    /  \1000
          1000\   /1   \(r1-r2 1000)
               r2 ──────┘
                 \1000
                  r3 (r3-d 1)
    s-n1 1  s-n2 1  s-n3 1000   n1-r1 1  n2-r1 1  n3-r1 1000
    n1-r2 1 r1-r2 1000 r2-r3 1000  n1-d 1  r3-d 1
  ```

  Scenario: Build the classic-SID TI-LFA topology and confirm adjacencies
    Given a clean test environment
    When I create namespace "s"
    And I create namespace "n1"
    And I create namespace "n2"
    And I create namespace "n3"
    And I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I create namespace "d"
    And I connect namespace "s" interface "s-n1" to namespace "n1" interface "n1-s"
    And I connect namespace "s" interface "s-n2" to namespace "n2" interface "n2-s"
    And I connect namespace "s" interface "s-n3" to namespace "n3" interface "n3-s"
    And I connect namespace "n1" interface "n1-r1" to namespace "r1" interface "r1-n1"
    And I connect namespace "n2" interface "n2-r1" to namespace "r1" interface "r1-n2"
    And I connect namespace "n3" interface "n3-r1" to namespace "r1" interface "r1-n3"
    And I connect namespace "n1" interface "n1-r2" to namespace "r2" interface "r2-n1"
    And I connect namespace "r1" interface "r1-r2" to namespace "r2" interface "r2-r1"
    And I connect namespace "r2" interface "r2-r3" to namespace "r3" interface "r3-r2"
    And I connect namespace "n1" interface "n1-d" to namespace "d" interface "d-n1"
    And I connect namespace "r3" interface "r3-d" to namespace "d" interface "d-r3"
    And I start zebra-rs in namespace "s"
    And I start zebra-rs in namespace "n1"
    And I start zebra-rs in namespace "n2"
    And I start zebra-rs in namespace "n3"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I start zebra-rs in namespace "d"
    And I apply config "s.yaml" to namespace "s"
    And I apply config "n1.yaml" to namespace "n1"
    And I apply config "n2.yaml" to namespace "n2"
    And I apply config "n3.yaml" to namespace "n3"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    And I apply config "d.yaml" to namespace "d"
    And I wait 30 seconds
    Then ping from "s" to "2001:db8:1::2" should succeed
    And ping from "s" to "2001:db8::8" should eventually succeed
    And ping from "d" to "2001:db8::1" should eventually succeed

  Scenario: Classic End/End.X SIDs exist and the repair is uncompressed
    Given the test topology exists
    # Classic full SIDs — the show output must say End / End.X, never
    # the micro-SID uN / uA forms (and no LIB twin rows, which only
    # uSID locators install).
    Then show command "show segment-routing srv6 sid" in namespace "s" should contain "End"
    And show command "show segment-routing srv6 sid" in namespace "s" should contain "End.X"
    And show command "show segment-routing srv6 sid" in namespace "s" should not contain "uN"
    And show command "show segment-routing srv6 sid" in namespace "s" should not contain "uA"
    # Repairs resolved to SRv6 segments.
    And show command "show ospfv3 repair-list detail" in namespace "s" should contain "srv6"
    And show command "show ospfv3 repair-list" in namespace "s" should contain "2001:db8::8/128"
    # No NEXT-C-SID packing for classic behaviors: the repair to d
    # rides one full 128-bit SID per segment — 3 repair segments plus
    # the original destination = an SRH of 4 segments (the uSID
    # sibling compresses the same repair into a single carrier).
    And kernel route "2001:db8::8" in namespace "s" should eventually contain "mode inline"
    And kernel route "2001:db8::8" in namespace "s" should eventually contain "segs 4 ["

  Scenario: Fast-reroute survives the primary link failure (s-n1)
    Given the test topology exists
    Then ping from "s" to "2001:db8::8" should succeed
    When I make namespace "s" interface "s-n1" down
    And I wait 5 seconds
    Then ping from "s" to "2001:db8::8" should succeed
    When I make namespace "s" interface "s-n1" up
    And I wait 30 seconds
    Then ping from "s" to "2001:db8::8" should eventually succeed

  Scenario: Promoted backup actually forwards over the classic SRv6 repair
    Given the test topology exists
    # Pin traffic onto the repair with every link up — proving each
    # full-SID hop (classic End at r1, classic End.X at r1 and r2,
    # all installed with neighbor-global nexthops) forwards.
    When I apply command "set router ospfv3 fast-reroute backup-as-primary" in namespace "s"
    And I wait 5 seconds
    # The promoted SRv6 repair is the protected primary and references
    # a protection indirection group; iproute2 renders v6 group routes
    # on two lines (route attrs on the first, nexthop detail on the
    # continuation), so assert the two halves separately.
    Then kernel route "2001:db8::8" in namespace "s" should eventually contain "proto ospf metric 2"
    And kernel route "2001:db8::8" in namespace "s" should eventually contain "dev s-n2"
    And kernel route "2001:db8::8" in namespace "s" should eventually contain "segs 4 ["
    And ping from "s" to "2001:db8::8" should eventually succeed
    # Restore install-side ordering.
    When I apply command "delete router ospfv3 fast-reroute backup-as-primary" in namespace "s"
    And I wait 5 seconds
    Then ping from "s" to "2001:db8::8" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "s"
    And I stop zebra-rs in namespace "n1"
    And I stop zebra-rs in namespace "n2"
    And I stop zebra-rs in namespace "n3"
    And I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I stop zebra-rs in namespace "d"
    And I delete namespace "s"
    And I delete namespace "n1"
    And I delete namespace "n2"
    And I delete namespace "n3"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    And I delete namespace "d"
    Then the test environment should be clean
