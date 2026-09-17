@bgp_ls_te_metric
@isis
Feature: BGP-LS carries the IS-IS TE performance metrics
  As an operator exporting topology to a PCE or controller, I want the
  RFC 8570 link performance metrics my IGP advertises to reach the
  BGP-LS Loc-RIB as RFC 8571 attributes, so a controller peering over
  BGP-LS sees how each link is actually performing and not just its
  IGP cost.

  Two zebra-rs instances share one P2P link, run IS-IS L2 over it with
  static te-metric values, and each runs `router bgp` with the
  link-state address family so the IS-IS producer is wired up. Each
  router translates its own LSDB into Link-State objects and installs
  them in its BGP-LS Loc-RIB, where `show bgp link-state` renders the
  translated attributes.

  The two ends advertise deliberately different delays, so each value
  can be traced to the router that originated it and no assertion can
  pass on a default.

  The producer walks the whole LSDB, not just the self-originated part,
  so each router also translates the LSP its neighbour flooded to it.
  That makes this a real round trip for the IS-IS half: ls1 encodes the
  RFC 8570 sub-TLVs, ls2 parses them off the wire, and ls2's producer
  translates what it parsed into RFC 8571 attributes.

  SCOPE: what is *not* covered is the BGP wire. BGP-LS re-advertisement
  to peers is not implemented (see `route_bgpls_originate`,
  "Re-advertisement to peers is deferred"), so nothing here puts a
  BGP-LS Attribute into an UPDATE. The BGP-LS ASLA TLV (1122) encoding
  in particular rests on unit tests until an egress path exists to
  carry it.

  Topology:

    ls1 (10.71.0.1)                      ls2 (10.71.0.2)
      ls1-ls2  192.168.71.1/30 ---- 192.168.71.2/30  ls2-ls1

    ls1 link delay: avg 1000us, min/max 900/1200us
    ls2 link delay: avg 2000us, min/max 1800/2400us

  Config files: ls1.yaml  ls2.yaml

  Scenario: Build the topology
    Given a clean test environment
    When I create namespace "ls1"
    And I create namespace "ls2"
    And I connect namespace "ls1" interface "ls1-ls2" to namespace "ls2" interface "ls2-ls1"
    And I start zebra-rs in namespace "ls1"
    And I start zebra-rs in namespace "ls2"
    And I apply config "ls1.yaml" to namespace "ls1"
    And I apply config "ls2.yaml" to namespace "ls2"
    And I wait 10 seconds
    Then ping from "ls1" to "192.168.71.2" should succeed

  Scenario: The IS-IS adjacency comes up
    Given the test topology exists
    Then show command "show isis neighbor" in namespace "ls1" should eventually contain "ls2"
    And show command "show isis neighbor" in namespace "ls2" should eventually contain "ls1"

  Scenario: Each router originates its own link into the BGP-LS Loc-RIB
    Given the test topology exists
    # The producer runs off SpfDone, so the objects appear once IS-IS
    # has converged.
    Then show command "show bgp link-state" in namespace "ls1" should eventually contain "Link"
    And show command "show bgp link-state" in namespace "ls2" should eventually contain "Link"

  Scenario: The RFC 8570 delay reaches BGP-LS as RFC 8571 attributes
    Given the test topology exists
    # ls1 advertises avg 1000us and min/max 900/1200us; the summary
    # line renders the top-level TLVs 1114 and 1115 translated from the
    # IS-IS sub-TLVs 33 and 34.
    Then show command "show bgp link-state" in namespace "ls1" should eventually contain "delay 1000us"
    And show command "show bgp link-state" in namespace "ls1" should eventually contain "min/max-delay 900/1200us"
    # RFC 8570 §4.4 encodes loss in units of 0.000003 %, so 333 renders
    # as 0.000999 %.
    And show command "show bgp link-state" in namespace "ls1" should eventually contain "loss 0.000999%"
    # The summary names four TLVs and counts the rest. The two it counts
    # are the delay variation (1116, which has no summary line) and the
    # ASLA TLV (1122) holding the Flex-Algorithm-scoped copy — the only
    # end-to-end evidence that 1122 is produced at all. If a TLV is
    # added to the producer this number moves, and that is worth
    # noticing rather than papering over.
    And show command "show bgp link-state" in namespace "ls1" should eventually contain "+2 more"

  Scenario: A neighbour's delay survives the IGP wire and the translation
    Given the test topology exists
    # ls2's Loc-RIB holds both directions: its own link, and ls1's as
    # parsed from the LSP IS-IS flooded over. The second is the
    # interesting one — ls1 encoded those sub-TLVs, ls2 decoded them,
    # and ls2's producer translated what it decoded.
    Then show command "show bgp link-state" in namespace "ls2" should eventually contain "delay 2000us"
    And show command "show bgp link-state" in namespace "ls2" should eventually contain "min/max-delay 1800/2400us"
    And show command "show bgp link-state" in namespace "ls2" should eventually contain "delay 1000us"
    And show command "show bgp link-state" in namespace "ls2" should eventually contain "min/max-delay 900/1200us"
    # ... and the same in the other direction, so neither side is simply
    # rendering its own config back.
    And show command "show bgp link-state" in namespace "ls1" should eventually contain "delay 2000us"
    And show command "show bgp link-state" in namespace "ls1" should eventually contain "min/max-delay 1800/2400us"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ls1"
    And I stop zebra-rs in namespace "ls2"
    And I delete namespace "ls1"
    And I delete namespace "ls2"
    Then the test environment should be clean
