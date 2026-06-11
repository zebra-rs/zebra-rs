@tilfa_srv6
@isis
Feature: IS-IS TI-LFA fast-reroute over SRv6 with BGP L3 service traffic
  As a network operator
  I want eight zebra-rs instances running IS-IS Level-2 with SRv6
  locators and TI-LFA (RFC 9490) to pre-compute a topology-independent
  repair for the source's primary path as an SRv6 SID list (End /
  End.X SIDs, SRH-inserted), so that when the primary link fails the
  source still reaches the destination — including BGP-carried SRv6
  service traffic between LAN segments behind the source and the
  destination.

  This is the SRv6 sibling of @isis_tilfa (same eight-router topology
  and metrics, IPv6-only). Differences from the SR-MPLS version:
  - every IS-IS circuit is `network-type point-to-point`;
  - `segment-routing srv6 locator LOCx` replaces `segment-routing
    mpls`; each router owns locator fcbb:bbbb:X::/48 (behavior usid);
  - the TI-LFA repair resolves to an SRv6 SID list — End SID of the
    P-node plus End.X SIDs along the post-convergence path — installed
    as an SRH insertion (H.Insert) so the final End.X hop forwards the
    original packet on by plain IPv6 (no decap terminator needed);
  - s and d each have a stub LAN segment (a host namespace sh / dh);
    s and d speak iBGP over their loopbacks with `redistribute
    connected` and `segment-routing srv6 ipv6-unicast`, so each LAN
    prefix is carried in BGP with an End.DT6 service SID and the
    ingress H.Encaps LAN-to-LAN traffic onto the SRv6 underlay that
    TI-LFA protects.

  The metrics are tuned so a simple LFA is impossible: s reaches d via
  s-n1 (cost 2); protecting the s-n1 link requires an SR repair tunnel
  through the r-plane rather than a plain loop-free alternate.

  Test Topology (metric shown where != 1; loopback 2001:db8::X,
  locator fcbb:bbbb:X::/48):
  ```
   sh ── s (2001:db8::1, fcbb:bbbb:1::/48)
             1 / 1 \      \ 1000
              n1    n2     n3        (n1 ::2, n2 ::3, n3 ::4)
          1 / |1 \1  \1     \1000
       d ─┘ 1 |   \    \      \
  (2001:db8::8)│    \1000\      \
    fcbb:8::/48│     r1───────── (r1-n3 1000)   (r1 ::5)
   dh ── d 1 \ │    /  \1000
              r3   /1   \(r1-r2 1000)           (r2 ::6)
          1000\   /      \
               r2 ────────┘                     (r3 ::7)
                 \1000
                  r3 (r3-d 1)
    s-n1 1  s-n2 1  s-n3 1000   n1-r1 1  n2-r1 1  n3-r1 1000
    n1-r2 1 r1-r2 1000 r2-r3 1000  n1-d 1  r3-d 1
    s-LAN: 2001:db8:100::/64 (sh)   d-LAN: 2001:db8:200::/64 (dh)
  ```

  Scenario: Build the SRv6 TI-LFA topology and confirm IS-IS + BGP
    Given a clean test environment
    When I create namespace "s"
    And I create namespace "n1"
    And I create namespace "n2"
    And I create namespace "n3"
    And I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I create namespace "d"
    And I create namespace "sh"
    And I create namespace "dh"
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
    And I connect namespace "s" interface "lan0" to namespace "sh" interface "eth0"
    And I connect namespace "d" interface "lan0" to namespace "dh" interface "eth0"
    And I add address "2001:db8:100::2/64" to interface "eth0" in namespace "sh"
    And I add address "2001:db8:200::2/64" to interface "eth0" in namespace "dh"
    And I add route "::/0" via "2001:db8:100::1" in namespace "sh"
    And I add route "::/0" via "2001:db8:200::1" in namespace "dh"
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

  Scenario: SRv6 End/End.X SIDs exist and a TI-LFA SRv6 repair is installed
    Given the test topology exists
    # s owns its locator's End (uN) SID and carved an End.X (uA) SID
    # for each IPv6-capable adjacency.
    Then show command "show segment-routing srv6 sid" in namespace "s" should contain "uN"
    And show command "show segment-routing srv6 sid" in namespace "s" should contain "uA"
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
    # sh -> s (H.Encaps to d's End.DT6) -> IGP -> d (decap) -> dh, and
    # the reply mirrors it via s's End.DT6.
    And ping from "sh" to "2001:db8:200::2" should succeed
    And ping from "dh" to "2001:db8:100::2" should succeed

  Scenario: Fast-reroute survives the primary link failure (s-n1)
    Given the test topology exists
    Then ping from "s" to "2001:db8::8" should succeed
    And ping from "sh" to "2001:db8:200::2" should succeed
    When I make namespace "s" interface "s-n1" down
    And I wait 5 seconds
    # Reachability restored over the SRv6 repair / post-convergence
    # path (out a different interface than the failed s-n1) — both the
    # IGP loopback route and the BGP/SRv6 LAN-to-LAN service traffic,
    # whose H.Encaps outer destination resolves via the protected
    # locator route.
    Then ping from "s" to "2001:db8::8" should succeed
    And ping from "sh" to "2001:db8:200::2" should succeed
    When I make namespace "s" interface "s-n1" up
    And I wait 10 seconds
    # Primary restored.
    Then ping from "s" to "2001:db8::8" should succeed
    And ping from "sh" to "2001:db8:200::2" should succeed

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
    And I delete namespace "sh"
    And I delete namespace "dh"
    Then the test environment should be clean
