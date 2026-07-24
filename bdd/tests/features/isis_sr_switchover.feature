@isis_sr_switchover
@isis
Feature: Live switchover IS-IS SR-MPLS -> SRv6 (classic) -> SRv6 uSID -> SR-MPLS via vtyctl apply
  As a network operator
  I want to migrate a running IS-IS Segment Routing network between
  dataplanes by applying each node's ENTIRE configuration with
  `vtyctl apply -f` (the BDD `I apply config` step — a declarative
  whole-config replace: everything the new file omits is deleted), so
  an SR-MPLS domain can be moved to SRv6 classic SIDs, compressed to
  NEXT-C-SID micro-SIDs, and rolled back to SR-MPLS, with each
  transition tearing down the previous dataplane completely and
  bringing up the next one end to end.

  The per-node configurations are the playset trios (playset/
  isis-srmpls, isis-srv6-classic, isis-srv6-usid) on the RFC 9855
  topology: 8 core routers in IS-IS level-2-only. The three phases
  observably differ on node s:
  - SR-MPLS: v4 addressing; remote loopbacks carry Prefix-SID labels
    (d = index 800 -> 16800 against SRGB base 16000); the edge subnet
    rides a recursive static via d's loopback, inheriting the label
    stack into the kernel (`encap mpls`); the ILM holds the SR
    entries.
  - SRv6 classic: v6 addressing; locators fcbb:bbbb:X::/48 are plain
    routed prefixes; s owns a /128 End SID (seg6local) plus per-
    adjacency End.X SIDs; the edge LANs become an iBGP (s<->d,
    loopback-to-loopback) IPv6-unicast service with End.DT6 SIDs and
    H.Encaps ingress routes (`via seg6`).
  - SRv6 uSID: identical except `behavior: usid` on every locator —
    the End SID becomes a locator-wide /48 uN with the NEXT-C-SID
    flavor (`next-csid` in the kernel route) and the classic /128
    disappears; the BGP service layer is untouched by the diff and
    must survive the transition without a session flap.

  e1 (behind s) and e2 (behind d) are plain dual-stack host
  namespaces (no routing daemon) provisioned once with both edge
  addressings and default routes; whichever edge family the routers
  currently serve decides which of their pings forwards, so
  edge-to-edge reachability doubles as the phase's end-to-end proof
  and the retired family's ping must go dark.

  Test Topology (playset/isis-srmpls; metric shown where != 1;
  loopbacks 10.0.0.X / 2001:db8::X, Prefix-SID index X00, locators
  fcbb:bbbb:X::/48):
  ```
   e1 --- s
       1 / 1 \      \ 1000
        n1    n2     n3
    1 / |1 \1  \1     \1000
 d ─┘ 1 |   \    \      \
        |    \1000\      \
        r2    r1───────── (r1-n3 1000)
    1000 \   /1   \(r1-r2 1000)
          \ /      \
           r2 ──────┘
             \1000
              r3 (r3-d 1)   d --- e2
  ```

  Scenario: Build the topology, dual-stack edge hosts, and the SR-MPLS baseline
    Given a clean test environment
    When I create namespace "e1"
    And I create namespace "e2"
    And I create namespace "s"
    And I create namespace "n1"
    And I create namespace "n2"
    And I create namespace "n3"
    And I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I create namespace "d"
    And I connect namespace "e1" interface "e1-s" to namespace "s" interface "s-e1"
    And I connect namespace "d" interface "d-e2" to namespace "e2" interface "e2-d"
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
    # The edge hosts carry BOTH edge addressings for the whole feature;
    # the routers' current phase decides which family forwards.
    And I add address "172.16.0.1/24" to interface "e1-s" in namespace "e1"
    And I add address "2001:db8:100::100/64" to interface "e1-s" in namespace "e1"
    And I add route "0.0.0.0/0" via "172.16.0.2" in namespace "e1"
    And I add route "::/0" via "2001:db8:100::1" in namespace "e1"
    And I add address "172.16.1.2/24" to interface "e2-d" in namespace "e2"
    And I add address "2001:db8:200::100/64" to interface "e2-d" in namespace "e2"
    And I add route "0.0.0.0/0" via "172.16.1.1" in namespace "e2"
    And I add route "::/0" via "2001:db8:200::1" in namespace "e2"
    And I start zebra-rs in namespace "s"
    And I start zebra-rs in namespace "n1"
    And I start zebra-rs in namespace "n2"
    And I start zebra-rs in namespace "n3"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I start zebra-rs in namespace "d"
    And I apply config "s-srmpls.yaml" to namespace "s"
    And I apply config "n1-srmpls.yaml" to namespace "n1"
    And I apply config "n2-srmpls.yaml" to namespace "n2"
    And I apply config "n3-srmpls.yaml" to namespace "n3"
    And I apply config "r1-srmpls.yaml" to namespace "r1"
    And I apply config "r2-srmpls.yaml" to namespace "r2"
    And I apply config "r3-srmpls.yaml" to namespace "r3"
    And I apply config "d-srmpls.yaml" to namespace "d"
    And I wait 10 seconds
    Then ping from "s" to "10.0.0.2" should eventually succeed
    And ping from "e1" to "172.16.0.2" should eventually succeed
    And ping from "e2" to "172.16.1.1" should eventually succeed

  Scenario: SR-MPLS phase forwards labeled traffic end to end
    Given the test topology exists
    # d's loopback rides its Prefix-SID: index 800 against SRGB base
    # 16000 = label 16800, single path out s-n1 at metric 12.
    Then show command "show ip route 10.0.0.8/32" in namespace "s" should eventually contain "[115/12] via 192.168.0.2, s-n1, label 16800"
    And show command "show mpls ilm" in namespace "s" should eventually contain "16800"
    # The edge subnet's static nexthop 10.0.0.8 is not on-link: it
    # resolves recursively through the IS-IS SR route and inherits the
    # label stack all the way into the kernel FIB.
    And show command "show ip route 172.16.1.0/24" in namespace "s" should eventually contain "via 10.0.0.8 (recursive)"
    And show command "show ip route 172.16.1.0/24" in namespace "s" should contain "label 16800"
    And kernel route "172.16.1.0/24" in namespace "s" should eventually contain "encap mpls"
    And kernel route "172.16.1.0/24" in namespace "s" should eventually contain "16800"
    # End to end: e1 -> s (push 16800) -> n1 (PHP) -> d -> e2, return
    # over d's mirrored static (label 16100 toward s).
    And ping from "s" to "10.0.0.8" should eventually succeed
    And ping from "e1" to "172.16.1.2" should eventually succeed
    And ping from "e2" to "172.16.0.1" should succeed

  Scenario: Switch over to SRv6 classic — whole-config replace swaps the dataplane
    Given the test topology exists
    # One `vtyctl apply -f` per node: the SRv6 file omits every v4
    # interface address, the SR-MPLS enable, and the statics, so the
    # replace deletes them and configures locators/BGP in one commit.
    When I apply config "s-srv6.yaml" to namespace "s"
    And I apply config "n1-srv6.yaml" to namespace "n1"
    And I apply config "n2-srv6.yaml" to namespace "n2"
    And I apply config "n3-srv6.yaml" to namespace "n3"
    And I apply config "r1-srv6.yaml" to namespace "r1"
    And I apply config "r2-srv6.yaml" to namespace "r2"
    And I apply config "r3-srv6.yaml" to namespace "r3"
    And I apply config "d-srv6.yaml" to namespace "d"
    And I wait 10 seconds
    # The v6 IGP converges: d's loopback is a plain IPv6 route (no
    # encapsulation — SRv6 encapsulates only where a SID says so), and
    # d's locator is an ordinary routed /48.
    Then show command "show ipv6 route 2001:db8::8/128" in namespace "s" should eventually contain "[115/12]"
    And show command "show ipv6 route 2001:db8::8/128" in namespace "s" should contain "s-n1"
    And show command "show ipv6 route fcbb:bbbb:8::/48" in namespace "s" should eventually contain "[115/2]"
    # s instantiates classic full-length SIDs from its locator: the
    # /128 End SID as a kernel seg6local route, End.X per adjacency —
    # and never the micro-SID forms.
    And show command "show segment-routing srv6 sid" in namespace "s" should eventually contain "End.X"
    And show command "show segment-routing srv6 sid" in namespace "s" should not contain "uN"
    And kernel route "fcbb:bbbb:1::" in namespace "s" should eventually contain "seg6local"
    # The SR-MPLS dataplane is fully torn down by the replace: the
    # labeled static and the v4 loopback route leave the kernel and
    # the ILM empties.
    And kernel route "172.16.1.0/24" in namespace "s" should eventually be gone
    And kernel route "10.0.0.8" in namespace "s" should eventually be gone
    And mpls ilm in namespace "s" should be empty
    And ping from "s" to "2001:db8::8" should eventually succeed
    # The retired v4 edge goes dark — s no longer serves 172.16.0.0/24.
    And ping from "e1" to "172.16.1.2" should fail

  Scenario: The BGP SRv6 service layer carries the edge LANs after the switchover
    Given the test topology exists
    # The s<->d iBGP session dials loopback-to-loopback. Each side's
    # first connect raced its own IGP convergence and a failed dial
    # parks the FSM in ConnectRetry — clear both now that the previous
    # scenario proved the loopback routes, so the session re-dials
    # immediately.
    When I run "clear bgp ipv6 neighbor 2001:db8::8" in namespace "s"
    And I run "clear bgp ipv6 neighbor 2001:db8::1" in namespace "d"
    Then BGP session in "s" to "2001:db8::8" should eventually be "Established"
    And BGP session in "d" to "2001:db8::1" should eventually be "Established"
    # d redistributes its connected LAN with an End.DT6 SID carved
    # from its locator; s installs the H.Encaps ingress route.
    And show command "show bgp ipv6 2001:db8:200::/64" in namespace "s" should eventually contain "End.DT6"
    And show command "show ipv6 route 2001:db8:200::/64" in namespace "s" should eventually contain "via seg6"
    # Edge-to-edge over the SRv6 service: e1 -> s (H.Encaps toward d's
    # End.DT6) -> locator routing -> d (decap) -> e2, and the reply
    # mirrors it via s's End.DT6.
    And ping from "e1" to "2001:db8:200::100" should eventually succeed
    And ping from "e2" to "2001:db8:100::100" should succeed

  Scenario: Switch over to SRv6 uSID — locators recompress, the service layer never flaps
    Given the test topology exists
    # The uSID files differ from classic by exactly one line per node:
    # `behavior: usid` on the locator. The replace diff touches only
    # the locator — BGP is identical, so the session must survive.
    When I apply config "s-usid.yaml" to namespace "s"
    And I apply config "n1-usid.yaml" to namespace "n1"
    And I apply config "n2-usid.yaml" to namespace "n2"
    And I apply config "n3-usid.yaml" to namespace "n3"
    And I apply config "r1-usid.yaml" to namespace "r1"
    And I apply config "r2-usid.yaml" to namespace "r2"
    And I apply config "r3-usid.yaml" to namespace "r3"
    And I apply config "d-usid.yaml" to namespace "d"
    And I wait 10 seconds
    # Micro-SID forms replace the classic ones: the End SID becomes a
    # locator-wide /48 uN with the NEXT-C-SID flavor and the classic
    # /128 End route disappears from the kernel.
    Then show command "show segment-routing srv6 sid" in namespace "s" should eventually contain "uN"
    # Poll for the same reason as isis_srv6_replace: `uN` is the node SID,
    # `uA` the adjacency SID, which only exists once the adjacency is Up.
    And show command "show segment-routing srv6 sid" in namespace "s" should eventually contain "uA"
    And kernel route "fcbb:bbbb:1::/48" in namespace "s" should eventually contain "next-csid"
    And kernel route "fcbb:bbbb:1::" in namespace "s" should eventually be gone
    And show command "show ipv6 route fcbb:bbbb:8::/48" in namespace "s" should eventually contain "[115/2]"
    # Service continuity: the iBGP session is still up (not re-
    # established) and the End.DT6 ingress route still forwards.
    And BGP session in "s" to "2001:db8::8" should be "Established"
    And show command "show ipv6 route 2001:db8:200::/64" in namespace "s" should eventually contain "via seg6"
    And ping from "s" to "2001:db8::8" should eventually succeed
    And ping from "e1" to "2001:db8:200::100" should eventually succeed

  Scenario: Roll back to SR-MPLS — labels return, SRv6 and BGP are torn down
    Given the test topology exists
    When I apply config "s-srmpls.yaml" to namespace "s"
    And I apply config "n1-srmpls.yaml" to namespace "n1"
    And I apply config "n2-srmpls.yaml" to namespace "n2"
    And I apply config "n3-srmpls.yaml" to namespace "n3"
    And I apply config "r1-srmpls.yaml" to namespace "r1"
    And I apply config "r2-srmpls.yaml" to namespace "r2"
    And I apply config "r3-srmpls.yaml" to namespace "r3"
    And I apply config "d-srmpls.yaml" to namespace "d"
    And I wait 10 seconds
    # The original SR-MPLS state is fully restored: labeled loopback
    # route, ILM entries, and the recursive static's inherited label
    # stack back in the kernel.
    Then show command "show ip route 10.0.0.8/32" in namespace "s" should eventually contain "[115/12] via 192.168.0.2, s-n1, label 16800"
    And show command "show mpls ilm" in namespace "s" should eventually contain "16800"
    And show command "show ip route 172.16.1.0/24" in namespace "s" should eventually contain "via 10.0.0.8 (recursive)"
    And kernel route "172.16.1.0/24" in namespace "s" should eventually contain "encap mpls"
    # The SRv6 dataplane and the BGP service layer are gone: the uN
    # /48 leaves the kernel, no SIDs remain, and the BGP instance
    # itself is deconfigured by the replace.
    And kernel route "fcbb:bbbb:1::/48" in namespace "s" should eventually be gone
    And show command "show segment-routing srv6 sid" in namespace "s" should not contain "fcbb"
    And show command "show bgp ipv6 summary" in namespace "s" should eventually contain "BGP is not configured or running"
    And ping from "s" to "10.0.0.8" should eventually succeed
    And ping from "e1" to "172.16.1.2" should eventually succeed
    And ping from "e2" to "172.16.0.1" should succeed
    # The v6 edge service went dark with the rollback.
    And ping from "e1" to "2001:db8:200::100" should fail

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
    And I delete namespace "e1"
    And I delete namespace "e2"
    And I delete namespace "s"
    And I delete namespace "n1"
    And I delete namespace "n2"
    And I delete namespace "n3"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    And I delete namespace "d"
    Then the test environment should be clean
