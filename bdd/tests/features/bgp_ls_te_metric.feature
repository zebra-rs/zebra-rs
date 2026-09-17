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

  A third node, lsc, plays the collector: it runs no IGP at all and
  peers with ls1 over BGP-LS alone, which is how a PCE or controller
  actually attaches. It sits in a different AS and enforces first-AS, so
  the feed has to carry a well-formed AS_PATH with ls1's AS at the
  front — an originated object whose AS_PATH was left empty is rejected
  outright, and the session shows it. Everything in its RIB arrived over the wire, so
  that is where the BGP half of the round trip can be observed — the
  RFC 8571 attributes and the RFC 9294 ASLA TLV emitted into an UPDATE,
  parsed by the receiver, and rendered from the decode.

  ls1 and ls2 also peer with each other, but neither can show a received
  object as best: each produces the whole LSDB itself, so its own
  Originated copy of every object wins path selection. That is correct,
  and it is why the collector is necessary rather than convenient.

  SCOPE: only self-originated objects are advertised. Re-advertising a
  *received* object is route reflection, which is not implemented — so
  lsc learns ls1's view of the topology, including the links ls1 learned
  from ls2's LSP, but would learn nothing through ls2.

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
    And I create namespace "lsc"
    And I connect namespace "ls1" interface "ls1-ls2" to namespace "ls2" interface "ls2-ls1"
    And I connect namespace "ls1" interface "ls1-lsc" to namespace "lsc" interface "lsc-ls1"
    And I start zebra-rs in namespace "ls1"
    And I start zebra-rs in namespace "ls2"
    And I start zebra-rs in namespace "lsc"
    And I apply config "ls1.yaml" to namespace "ls1"
    And I apply config "ls2.yaml" to namespace "ls2"
    And I apply config "lsc.yaml" to namespace "lsc"
    And I wait 10 seconds
    Then ping from "ls1" to "192.168.71.2" should succeed
    And ping from "lsc" to "192.168.73.1" should succeed

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

  Scenario: The BGP-LS session comes up
    Given the test topology exists
    Then show command "show bgp summary" in namespace "ls1" should eventually contain "10.71.0.2"
    And show command "show bgp summary" in namespace "ls2" should eventually contain "10.71.0.1"
    And show command "show bgp summary" in namespace "lsc" should eventually contain "192.168.73.1"

  Scenario: The collector learns the topology over BGP
    Given the test topology exists
    # lsc runs no IGP, so every object here arrived in an UPDATE. They
    # name ls1 as the advertiser, where a locally produced object would
    # render `from 0.0.0.0`.
    Then show command "show bgp link-state" in namespace "lsc" should eventually contain "from 192.168.73.1"
    And show command "show bgp link-state" in namespace "lsc" should eventually contain "Node"
    And show command "show bgp link-state" in namespace "lsc" should eventually contain "Link"
    # ls1 originates its whole LSDB view, so both directions reach the
    # collector even though only ls1 advertises to it.
    And show command "show bgp link-state" in namespace "lsc" should eventually contain "0000.0000.0001"
    And show command "show bgp link-state" in namespace "lsc" should eventually contain "0000.0000.0002"

  Scenario: The RFC 8571 attributes survive the BGP wire
    Given the test topology exists
    # These bytes were encoded by ls1, put into an UPDATE, parsed by
    # lsc, and rendered from the decode — the first time anything reads
    # back what the RFC 8571 / RFC 9294 encoders produce.
    Then show command "show bgp link-state" in namespace "lsc" should eventually contain "min/max-delay 900/1200us"
    And show command "show bgp link-state" in namespace "lsc" should eventually contain "min/max-delay 1800/2400us"
    And show command "show bgp link-state" in namespace "lsc" should eventually contain "delay 1000us"
    And show command "show bgp link-state" in namespace "lsc" should eventually contain "loss 0.000999%"
    # The ASLA TLV (1122) rides along and is counted, not decoded, by
    # the summary — the same "+2 more" the originator shows.
    And show command "show bgp link-state" in namespace "lsc" should eventually contain "+2 more"

  Scenario: An outbound deny withdraws what was already advertised
    Given the test topology exists
    # Bind a policy whose only clause denies unconditionally. The
    # collector already holds the topology, so honouring the edit means
    # taking it back — not merely declining to send it again. Before
    # the Adj-RIB-Out existed, an accepted deny left the feed in place
    # until the session reset.
    When I apply command "set policy DENYALL entry 10 action deny" in namespace "ls1"
    And I apply command "set router bgp neighbor 192.168.73.2 afi-safi link-state policy out DENYALL" in namespace "ls1"
    Then show command "show bgp link-state" in namespace "lsc" should eventually contain "no link-state objects"

  Scenario: Removing the deny restores the feed
    Given the test topology exists
    When I apply command "delete router bgp neighbor 192.168.73.2 afi-safi link-state policy out" in namespace "ls1"
    Then show command "show bgp link-state" in namespace "lsc" should eventually contain "min/max-delay 900/1200us"
    And show command "show bgp link-state" in namespace "lsc" should eventually contain "from 192.168.73.1"

  Scenario: A conditional clause does not act unconditionally
    Given the test topology exists
    # Entry 10 denies only paths of length 100 or more; ours is one hop
    # long, so it must not fire and entry 20 must permit. An evaluator
    # that ignores the condition it cannot be bothered to read treats
    # entry 10 as matching everything and the feed disappears.
    When I apply command "set policy LONGPATH entry 10 action deny" in namespace "ls1"
    And I apply command "set policy LONGPATH entry 10 match as-path-len ge 100" in namespace "ls1"
    And I apply command "set policy LONGPATH entry 20 action permit" in namespace "ls1"
    And I apply command "set router bgp neighbor 192.168.73.2 afi-safi link-state policy out LONGPATH" in namespace "ls1"
    Then show command "show bgp link-state" in namespace "lsc" should eventually contain "min/max-delay 900/1200us"
    And show command "show bgp link-state" in namespace "lsc" should eventually not contain "no link-state objects"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ls1"
    And I stop zebra-rs in namespace "ls2"
    And I stop zebra-rs in namespace "lsc"
    And I delete namespace "ls1"
    And I delete namespace "ls2"
    And I delete namespace "lsc"
    Then the test environment should be clean
