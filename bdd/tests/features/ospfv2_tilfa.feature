@serial
@ospfv2_tilfa
Feature: OSPFv2 TI-LFA fast-reroute over SR-MPLS
  As a network operator
  I want five zebra-rs instances running OSPFv2 with SR-MPLS (RFC 8665)
  and TI-LFA (RFC 9490) to pre-compute a topology-independent loop-free
  repair for the source's primary path, so that when the primary link
  fails the source still reaches the destination over the SR repair /
  post-convergence path.

  IPv4 sibling of `ospfv3_tilfa.feature` — same five-node ring, same
  SID plan, the v2 SR machinery (Extended-Prefix / Extended-Link
  Opaque LSAs instead of RFC 8362 E-LSAs). All links run at the
  default interface cost so the ring topology — not metrics — rules a
  plain LFA out. Every router enables `segment-routing mpls` and
  `fast-reroute ti-lfa`; loopback Prefix-SIDs index 100..500 resolve
  against the default SRGB (base 16000), and each ring interface
  carries an Adjacency-SID (index = <from><to> digit pair) — the
  repair encodes its last hop as an Adj-SID segment, which only
  resolves when the penultimate repair node advertises one.

  OSPFv2 TI-LFA excludes the primary first-hop *vertex* (node
  protection), so repairs exist exactly for the non-adjacent
  destinations n2 and n3.

  Test Topology (loopback 10.0.0.X / SID X00 / router-id 10.0.0.X):
  ```
        s (.1) ────────── d (.5)         s-d:   192.168.5.0/30
         │                 │             s-n1:  192.168.1.0/30
        n1 (.2)           n3 (.4)        n1-n2: 192.168.2.0/30
         │                 │             n2-n3: 192.168.3.0/30
        n2 (.3) ───────────┘             n3-d:  192.168.4.0/30
  ```
  s reaches n3 (10.0.0.4) via s-d (cost 20); protecting that first
  hop, the repair tunnels via n1 with [Node-SID(n2) 16300,
  Adj-SID(n2->n3)] and is installed as the route's backup nexthop.

  Scenario: Build the TI-LFA ring and confirm adjacencies + routes
    Given a clean test environment
    When I create namespace "s"
    And I create namespace "n1"
    And I create namespace "n2"
    And I create namespace "n3"
    And I create namespace "d"
    And I connect namespace "s" interface "s-n1" to namespace "n1" interface "n1-s"
    And I connect namespace "n1" interface "n1-n2" to namespace "n2" interface "n2-n1"
    And I connect namespace "n2" interface "n2-n3" to namespace "n3" interface "n3-n2"
    And I connect namespace "n3" interface "n3-d" to namespace "d" interface "d-n3"
    And I connect namespace "d" interface "d-s" to namespace "s" interface "s-d"
    And I start zebra-rs in namespace "s"
    And I start zebra-rs in namespace "n1"
    And I start zebra-rs in namespace "n2"
    And I start zebra-rs in namespace "n3"
    And I start zebra-rs in namespace "d"
    And I apply config "s.yaml" to namespace "s"
    And I apply config "n1.yaml" to namespace "n1"
    And I apply config "n2.yaml" to namespace "n2"
    And I apply config "n3.yaml" to namespace "n3"
    And I apply config "d.yaml" to namespace "d"
    And I wait 30 seconds
    # Directly-connected adjacency over s-n1, then a multi-hop loopback
    # (n2, two hops away) over the converged RIB.
    Then ping from "s" to "192.168.1.2" should succeed
    And ping from "s" to "10.0.0.3" should succeed

  Scenario: SR-MPLS labels and a TI-LFA repair are installed on the source
    Given the test topology exists
    # Remote node-SIDs resolved into the LFIB. Multi-hop destinations
    # swap (label kept toward the owner); a directly-adjacent owner's
    # SID renders as an implicit-null Pop — v2 marks adjacency
    # nexthops and applies the PHP optimisation there (unlike v3,
    # which pushes the explicit label all the way per its NP flag).
    Then mpls ilm in namespace "s" should contain label 16300
    And mpls ilm in namespace "s" should contain label 16500
    And mpls ilm outgoing label for label 16100 in namespace "s" should be "Pop"
    And mpls ilm outgoing label for label 16300 in namespace "s" should be "16300"
    And mpls ilm outgoing label for label 16500 in namespace "s" should be "Pop"
    # The graph-level TI-LFA computation found repairs that need an SR
    # tunnel: a Node-SID to reach past the failure, then an Adj-SID for
    # the final hop.
    And show command "show ip ospf ti-lfa" in namespace "s" should contain "OSPF TI-LFA repair paths:"
    And show command "show ip ospf ti-lfa" in namespace "s" should contain "Node-SID"
    And show command "show ip ospf ti-lfa" in namespace "s" should contain "Adj-SID"
    # And the repairs are installed against the non-adjacent loopbacks:
    # n2's (protected against s-n1 loss) and n3's (protected against
    # s-d loss, tunnelling via n1 with n2's node-SID label 16300).
    And show command "show ip ospf repair-list" in namespace "s" should contain "10.0.0.3/32"
    And show command "show ip ospf repair-list" in namespace "s" should contain "10.0.0.4/32"
    And show command "show ip ospf repair-list" in namespace "s" should contain "16300"
    And show command "show ip ospf repair-list detail" in namespace "s" should contain "sr-mpls"

  Scenario: Source reaches the destination over the primary path
    Given the test topology exists
    # s -> d primary is the direct s-d link (one hop); s -> n3 rides
    # the same link one hop further.
    Then ping from "s" to "10.0.0.5" should succeed
    And ping from "s" to "10.0.0.4" should succeed
    And ping from "d" to "10.0.0.1" should succeed

  Scenario: Fast-reroute survives the primary link failure (s-d)
    Given the test topology exists
    Then ping from "s" to "10.0.0.4" should succeed
    When I make namespace "s" interface "s-d" down
    And I wait 5 seconds
    # n3's loopback was TI-LFA-protected (backup via n1 pre-installed);
    # d's loopback is the failed first hop itself (no repair exists for
    # an adjacent destination) and recovers via reconvergence. Both end
    # up on the long way around (s-n1-n2-n3[-d]), out a different
    # interface than the failed s-d.
    Then ping from "s" to "10.0.0.4" should succeed
    And ping from "s" to "10.0.0.5" should succeed
    When I make namespace "s" interface "s-d" up
    And I wait 30 seconds
    # Primary restored once the adjacency re-forms.
    Then ping from "s" to "10.0.0.5" should succeed

  Scenario: Disabling fast-reroute clears the repair-list
    Given the test topology exists
    # s still holds TI-LFA backups from the previous scenarios.
    Then show command "show ip ospf repair-list" in namespace "s" should contain "16300"
    # Re-apply s without `fast-reroute ti-lfa` (SR-MPLS stays on).
    When I apply config "s-nofrr.yaml" to namespace "s"
    And I wait 5 seconds
    # The toggle re-runs SPF without the TI-LFA pass: no graph repairs,
    # no installed backups — while the SR labels stay in the LFIB.
    Then show command "show ip ospf ti-lfa" in namespace "s" should contain "(no TI-LFA repair paths computed)"
    And show command "show ip ospf repair-list" in namespace "s" should contain "(no TI-LFA repair-list entries)"
    And mpls ilm in namespace "s" should contain label 16300

  Scenario: Deleting segment-routing mpls clears all MPLS ILM entries
    Given the test topology exists
    # s still has remote node-SID labels installed (n2 SID 300 -> 16300,
    # d SID 500 -> 16500).
    Then mpls ilm in namespace "s" should contain label 16300
    And mpls ilm in namespace "s" should contain label 16500
    # Remove `segment-routing mpls` from s entirely.
    When I apply config "s-nosr.yaml" to namespace "s"
    And I wait 5 seconds
    # Disabling SR-MPLS must withdraw every MPLS ILM entry, leaving the
    # LFIB completely empty.
    Then mpls ilm in namespace "s" should be empty

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "s"
    And I stop zebra-rs in namespace "n1"
    And I stop zebra-rs in namespace "n2"
    And I stop zebra-rs in namespace "n3"
    And I stop zebra-rs in namespace "d"
    And I delete namespace "s"
    And I delete namespace "n1"
    And I delete namespace "n2"
    And I delete namespace "n3"
    And I delete namespace "d"
    Then the test environment should be clean
