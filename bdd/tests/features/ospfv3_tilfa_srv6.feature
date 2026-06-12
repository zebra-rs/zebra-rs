@srv6_tilfa_v3
Feature: OSPFv3 TI-LFA fast-reroute over SRv6
  As a network operator
  I want eight zebra-rs instances running OSPFv3 with SRv6 locators
  (RFC 9513) and TI-LFA (RFC 9490) to pre-compute a topology-
  independent repair for the source's primary path as an SRv6 SID
  list — End/uN of the P-node plus uA hops, NEXT-C-SID-compressed and
  SRH-inserted — so that when the primary link fails the source still
  reaches the destination.

  Phases 5+6 of `docs/design/ospfv3-srv6-plan.md`: the OSPFv3 sibling
  of `isis_tilfa_srv6.feature` (same eight-router RFC 9855 §5
  topology and metrics as `ospfv3_tilfa.feature`, with the SR-MPLS
  machinery replaced by uSID locators fcbb:bbbb:X::/48). Repairs ride
  the carriers validated for IS-IS in #1364, the End.X kernel entries
  carry neighbor-global nexthops per #1361, and the promoted-backup
  scenario proves the repair dataplane genuinely forwards — the
  coverage rule every TI-LFA feature carries since #1361.

  Test Topology (cost shown where != 1; loopback 2001:db8::X /
  locator fcbb:bbbb:X::/48 / router-id 10.0.0.X):
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

  Scenario: Build the TI-LFA topology and confirm adjacencies + SRv6
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
    # Direct adjacency over s-n1, then d's loopback across the area.
    Then ping from "s" to "2001:db8:1::2" should succeed
    And ping from "s" to "2001:db8::8" should eventually succeed
    And ping from "d" to "2001:db8::1" should eventually succeed

  Scenario: SRv6 SIDs exist and a TI-LFA SRv6 repair is installed
    Given the test topology exists
    # s owns its uN plus a uA (and its LIB twin) per Full adjacency.
    Then show command "show segment-routing srv6 sid" in namespace "s" should contain "uN"
    And show command "show segment-routing srv6 sid" in namespace "s" should contain "uA"
    And show command "show segment-routing srv6 sid" in namespace "s" should contain "uA(LIB)"
    # The graph repairs resolved to SRv6 segments, not labels.
    And show command "show ospfv3 repair-list detail" in namespace "s" should contain "srv6"
    And show command "show ospfv3 repair-list detail" in namespace "s" should not contain "sr-mpls"
    And show command "show ospfv3 repair-list" in namespace "s" should contain "2001:db8::8/128"
    # The s-n1-protected route to d carries the repair as an SRH
    # insertion in the kernel: the three repair uSIDs (uN of r1 + two
    # uAs) compress into one carrier, so the inserted SRH is carrier
    # + original destination = 2 segments.
    And kernel route "2001:db8::8" in namespace "s" should eventually contain "mode inline"
    And kernel route "2001:db8::8" in namespace "s" should eventually contain "segs 2 ["

  Scenario: Fast-reroute survives the primary link failure (s-n1)
    Given the test topology exists
    Then ping from "s" to "2001:db8::8" should succeed
    When I make namespace "s" interface "s-n1" down
    And I wait 5 seconds
    # Restored over the SRv6 repair / post-convergence path, out a
    # different interface than the failed s-n1.
    Then ping from "s" to "2001:db8::8" should succeed
    When I make namespace "s" interface "s-n1" up
    And I wait 30 seconds
    Then ping from "s" to "2001:db8::8" should eventually succeed

  Scenario: Promoted backup actually forwards over the SRv6 repair
    Given the test topology exists
    # Pin traffic onto the repair with every link up — the only test
    # that exercises the SID list itself (by ping time after a real
    # failure, SPF has already reconverged onto a plain primary).
    When I apply command "set router ospfv3 fast-reroute backup-as-primary" in namespace "s"
    And I wait 5 seconds
    # d's loopback now has the SRH-insert repair as its best kernel
    # entry, out the repair egress s-n2 at metric 2, demoted plain
    # primary behind it at 3.
    Then kernel route "2001:db8::8" in namespace "s" should eventually contain "dev s-n2 proto ospf metric 2"
    And kernel route "2001:db8::8" in namespace "s" should eventually contain "segs 2 ["
    # End-to-end over the carrier-encoded repair: dies if any uN/uA
    # hop (or the LIB twin install) fails to forward.
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
