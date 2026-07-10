@tilfa_classic_srv6
@isis
Feature: IS-IS TI-LFA fast-reroute over SRv6 classic (full) SIDs with BGP L3 service traffic
  As a network operator
  I want eight zebra-rs instances running IS-IS Level-2 with SRv6
  locators and TI-LFA (RFC 9855) to pre-compute a topology-independent
  repair for the source's primary path as an SRv6 SID list (End /
  End.X SIDs, SRH-inserted), so that when the primary link fails the
  source still reaches the destination — including BGP-carried SRv6
  service traffic between LAN segments behind the source and the
  destination.

  This is the classic-SID sibling of @tilfa_srv6 (same eight-router
  topology, metrics and addressing). The only configuration difference
  is the locator: `behavior usid` is omitted, so every router's
  locator fcbb:bbbb:X::/48 allocates SIDs in the classic RFC 8986
  full-SID layout instead of the RFC 9800 NEXT-C-SID (micro-SID)
  format. Observable consequences this feature pins:
  - `show segment-routing srv6 sid` lists the node SID as `End` and
    the per-adjacency SIDs as `End.X` (not `uN` / `uA`);
  - the End SID is the locator network address installed as a /128
    (no NEXT-CSID flavor), and each repair segment in the TI-LFA SID
    list is a full 128-bit SID — no uSID carrier compression;
  - everything else is unchanged: the repair is still an SRH
    insertion (H.Insert) ending on the original destination, and the
    BGP service SIDs are still End.DT6.

  The metrics are tuned so a simple LFA is impossible: s reaches d via
  s-n1 (cost 2); protecting the s-n1 link requires an SR repair tunnel
  through the r-plane rather than a plain loop-free alternate.

  Test Topology (metric shown where != 1; loopback 2001:db8::X,
  locator fcbb:bbbb:X::/48; e1 / e2 are the stub LAN hosts):
  ```
   e1 ── s (2001:db8::1, fcbb:bbbb:1::/48)
             1 / 1 \      \ 1000
              n1    n2     n3        (n1 ::2, n2 ::3, n3 ::4)
          1 / |1 \1  \1     \1000
       d ─┘ 1 |   \    \      \
  (2001:db8::8)│    \1000\      \
    fcbb:8::/48│     r1───────── (r1-n3 1000)   (r1 ::5)
   e2 ── d 1 \ │    /  \1000
              r3   /1   \(r1-r2 1000)           (r2 ::6)
          1000\   /      \
               r2 ────────┘                     (r3 ::7)
                 \1000
                  r3 (r3-d 1)
    s-n1 1  s-n2 1  s-n3 1000   n1-r1 1  n2-r1 1  n3-r1 1000
    n1-r2 1 r1-r2 1000 r2-r3 1000  n1-d 1  r3-d 1
    s-LAN: 2001:db8:100::/64 (e1)   d-LAN: 2001:db8:200::/64 (e2)
  ```

  Scenario: Build the classic-SID SRv6 TI-LFA topology and confirm IS-IS + BGP
    Given a clean test environment
    When I create namespace "s"
    And I create namespace "n1"
    And I create namespace "n2"
    And I create namespace "n3"
    And I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I create namespace "d"
    And I create namespace "e1"
    And I create namespace "e2"
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
    And I connect namespace "s" interface "lan0" to namespace "e1" interface "eth0"
    And I connect namespace "d" interface "lan0" to namespace "e2" interface "eth0"
    And I add address "2001:db8:100::2/64" to interface "eth0" in namespace "e1"
    And I add address "2001:db8:200::2/64" to interface "eth0" in namespace "e2"
    And I add route "::/0" via "2001:db8:100::1" in namespace "e1"
    And I add route "::/0" via "2001:db8:200::1" in namespace "e2"
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
    And I wait 25 seconds
    # The s<->d iBGP session dials loopback-to-loopback. The first
    # connect raced the IGP (no route to the peer loopback yet), and a
    # failed dial parks the FSM in ConnectRetry (120s RFC default) —
    # clear both sides now that the IGP has converged so the session
    # re-dials immediately.
    When I run "clear bgp ipv6 neighbor 2001:db8::8" in namespace "s"
    And I run "clear bgp ipv6 neighbor 2001:db8::1" in namespace "d"
    And I wait 15 seconds
    # Directly-connected adjacency over s-n1, then loopbacks across the
    # IS-IS IPv6 domain.
    Then ping from "s" to "2001:db8:0:1::2" should succeed
    And ping from "s" to "2001:db8::2" should succeed
    And ping from "s" to "2001:db8::8" should succeed
    And ping from "d" to "2001:db8::1" should succeed
    And BGP session in "s" to "2001:db8::8" should be "Established"
    And BGP session in "d" to "2001:db8::1" should be "Established"

  Scenario: Classic SRv6 End/End.X SIDs exist and a TI-LFA SRv6 repair is installed
    Given the test topology exists
    # s owns its locator's End SID and carved an End.X SID for each
    # IPv6-capable adjacency — classic full SIDs, so the show output
    # must say End / End.X, never the micro-SID uN / uA forms.
    Then show command "show segment-routing srv6 sid" in namespace "s" should contain "End"
    And show command "show segment-routing srv6 sid" in namespace "s" should contain "End.X"
    And show command "show segment-routing srv6 sid" in namespace "s" should not contain "uN"
    And show command "show segment-routing srv6 sid" in namespace "s" should not contain "uA"
    # The s-n1-protected IPv6 routes carry a pre-computed TI-LFA repair
    # expressed as an SRv6 SID list, installed by SRH insertion: the
    # repair segments are transit End/End.X SIDs, so the original
    # destination must remain the SRH's final segment (H.Encap would
    # blackhole at the last SID — Linux has no USD flavor).
    And show command "show isis route detail" in namespace "s" should contain "Backup path: TI-LFA"
    And show command "show isis route detail" in namespace "s" should contain "SID list"
    And show command "show isis route detail" in namespace "s" should contain "Encap: H.Insert"

  Scenario: BGP carries the LAN prefixes as SRv6 End.DT6 service routes
    Given the test topology exists
    # d redistributes its connected LAN prefix with an End.DT6 SID
    # carved from its locator; s (encapsulation-type srv6) accepts it
    # and installs an H.Encaps ingress route toward the SID.
    Then show command "show bgp ipv6 2001:db8:200::/64" in namespace "s" should contain "Remote SID"
    And show command "show bgp ipv6 2001:db8:200::/64" in namespace "s" should contain "End.DT6"
    And show command "show ipv6 route 2001:db8:200::/64" in namespace "s" should contain "via seg6"
    And show command "show bgp ipv6 2001:db8:100::/64" in namespace "d" should contain "Remote SID"
    # LAN-to-LAN service traffic rides the SRv6 underlay end-to-end:
    # e1 -> s (H.Encaps to d's End.DT6) -> IGP -> d (decap) -> e2, and
    # the reply mirrors it via s's End.DT6.
    And ping from "e1" to "2001:db8:200::2" should succeed
    And ping from "e2" to "2001:db8:100::2" should succeed

  Scenario: Fast-reroute survives the primary link failure (s-n1)
    Given the test topology exists
    Then ping from "s" to "2001:db8::8" should succeed
    And ping from "e1" to "2001:db8:200::2" should succeed
    When I make namespace "s" interface "s-n1" down
    And I wait 5 seconds
    # Reachability restored over the SRv6 repair / post-convergence
    # path (out a different interface than the failed s-n1) — both the
    # IGP loopback route and the BGP/SRv6 LAN-to-LAN service traffic,
    # whose H.Encaps outer destination resolves via the protected
    # locator route.
    Then ping from "s" to "2001:db8::8" should succeed
    And ping from "e1" to "2001:db8:200::2" should succeed
    When I make namespace "s" interface "s-n1" up
    And I wait 10 seconds
    # Primary restored.
    Then ping from "s" to "2001:db8::8" should succeed
    And ping from "e1" to "2001:db8:200::2" should succeed

  Scenario: Promoted backup actually forwards over the SRv6 repair
    Given the test topology exists
    # `backup-as-primary` swaps the metric-sort offset so each TI-LFA
    # repair installs as the active route and the SPF primary demotes
    # to metric+1; `clear isis spf` recomputes and reinstalls with the
    # flag applied. Traffic is pinned onto the SRv6 repair while every
    # link stays up — proving the SID list genuinely forwards, which
    # the link-failure scenario cannot (by ping time SPF has already
    # reconverged onto a plain post-convergence primary).
    When I apply command "set router isis fast-reroute backup-as-primary" in namespace "s"
    And I run "clear isis spf" in namespace "s"
    # d's loopback route now has the SRH-insert repair as its best
    # kernel entry: out the repair egress s-n2 at metric 12 (2 path +
    # 10 for d's loopback prefix), demoted plain primary behind at 13.
    Then kernel route "2001:db8::8" in namespace "s" should eventually contain "mode inline"
    # The promoted SRv6 repair is the protected primary and references
    # a protection indirection group; iproute2 renders v6 group routes
    # on two lines (route attrs on the first, nexthop detail on the
    # continuation), so assert the two halves separately.
    And kernel route "2001:db8::8" in namespace "s" should eventually contain "proto isis metric 12"
    And kernel route "2001:db8::8" in namespace "s" should eventually contain "dev s-n2"
    # End-to-end over the repair: the IGP loopback path and the
    # BGP/SRv6 LAN-to-LAN service traffic, whose H.Encaps outer
    # destination resolves via the promoted locator route. These die
    # if any repair-segment End/End.X hop fails to forward (e.g. the
    # kernel End.X nh6 lookup resolving on the wrong link).
    And ping from "s" to "2001:db8::8" should succeed
    And ping from "e1" to "2001:db8:200::2" should succeed

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
    And I delete namespace "e1"
    And I delete namespace "e2"
    Then the test environment should be clean
