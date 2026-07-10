@serial
@ospfv2_tilfa
Feature: OSPFv2 TI-LFA fast-reroute over SR-MPLS
  As a network operator
  I want eight zebra-rs instances running OSPFv2 with SR-MPLS (RFC 8665)
  and TI-LFA (RFC 9855) to pre-compute a topology-independent loop-free
  repair for the source's primary path, so that when the primary link
  fails the source still reaches the destination over the SR repair /
  post-convergence path.

  IPv4 OSPFv2 sibling of `isis_tilfa.feature` — the same eight-node
  RFC 9855 §5 topology, addressing, and metrics, with the v2 SR
  machinery (Extended-Prefix / Extended-Link Opaque LSAs instead of
  IS-IS sub-TLVs). All links are point-to-point; every router enables
  `segment-routing mpls` and `fast-reroute ti-lfa`. Loopback
  Prefix-SIDs index 100..800 resolve against the default SRGB (base
  16000). Adjacency-SIDs are NOT configured: each router allocates
  one per Full adjacency out of its SRLB (base 15000) automatically
  and advertises it as a local (V|L) Adj-SID — IS-IS-parity dynamic
  allocation — and the repair encodes its mid-path hops as those
  Adj-SID segments.

  The metrics are tuned so a simple LFA is impossible: s reaches d via
  s-n1 (cost 2); the only other neighbours (n2, n3) are equidistant /
  expensive, so protecting the s-n1 first hop requires an SR repair
  tunnel through the r-plane rather than a plain loop-free alternate.

  OSPFv2 TI-LFA excludes the primary first-hop *vertex* (node
  protection) and skips SPF-level ECMP destinations (the remaining
  legs already protect the prefix), so repairs exist exactly for r2,
  r3 and d — the single-nexthop destinations behind n1. Per RFC 9855
  §5.3, the repair for d is <Node-SID(r1), Adj-SID(r1-r2),
  Adj-SID(r2-r3)> via first-hop n2: labels [16500, 15xxx, 15yyy] —
  the Adj-SID values are whatever r1 / r2 carved from their SRLBs.

  Test Topology (metric shown where != 1; loopback 10.0.0.X / SID X00
  / router-id 10.0.0.X):
  ```
                 s (10.0.0.1)
             1 / 1 \      \ 1000
              n1    n2     n3
          1 / |1 \1  \1     \1000
       d ─┘ 1 |   \    \      \
    (10.0.0.8)│    \1000\      \
          1 \ │     r1───────── (r1-n3 1000)
             r3    /  \1000
          1000\   /1   \(r1-r2 1000)
               r2 ──────┘
                 \1000
                  r3 (r3-d 1)
    s-n1 1  s-n2 1  s-n3 1000   n1-r1 1  n2-r1 1  n3-r1 1000
    n1-r2 1 r1-r2 1000 r2-r3 1000  n1-d 1  r3-d 1
  ```

  Scenario: Build the TI-LFA topology and confirm adjacencies + routes
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
    # Directly-connected adjacency over s-n1, then a multi-hop loopback
    # (d, two hops away) over the converged RIB.
    Then ping from "s" to "192.168.0.2" should succeed
    And ping from "s" to "10.0.0.8" should succeed

  Scenario: SR-MPLS labels and a TI-LFA repair are installed on the source
    Given the test topology exists
    # Remote node-SIDs resolved into the LFIB. Multi-hop destinations
    # swap (label kept toward the owner); a directly-adjacent owner's
    # SID renders as an implicit-null Pop — v2 marks adjacency
    # nexthops and applies the PHP optimisation there (unlike v3,
    # which pushes the explicit label all the way per its NP flag).
    Then mpls ilm in namespace "s" should contain label 16500
    And mpls ilm in namespace "s" should contain label 16800
    And mpls ilm outgoing label for label 16100 in namespace "s" should be "Pop"
    And mpls ilm outgoing label for label 16200 in namespace "s" should be "Pop"
    And mpls ilm outgoing label for label 16800 in namespace "s" should be "16800"
    # The graph-level TI-LFA computation found repairs that need an SR
    # tunnel: a Node-SID to reach the P-node r1 past the failure, then
    # Adj-SIDs walking the expensive r-plane links.
    And show command "show ospf ti-lfa" in namespace "s" should contain "OSPF TI-LFA repair paths:"
    And show command "show ospf ti-lfa" in namespace "s" should contain "Node-SID"
    And show command "show ospf ti-lfa" in namespace "s" should contain "Adj-SID"
    # And the repairs are installed against the single-nexthop
    # loopbacks behind n1: r2, r3 and d (r1 itself is ECMP via n1/n2
    # and self-protects). Every repair starts with r1's node-SID label
    # 16500, followed by dynamically allocated SRLB Adj-SID labels
    # (15xxx — exact values depend on each router's allocation order,
    # so the assertion pins the SRLB range, not a specific label).
    And show command "show ospf repair-list" in namespace "s" should contain "10.0.0.6/32"
    And show command "show ospf repair-list" in namespace "s" should contain "10.0.0.7/32"
    And show command "show ospf repair-list" in namespace "s" should contain "10.0.0.8/32"
    And show command "show ospf repair-list" in namespace "s" should contain "[16500, 15"
    And show command "show ospf repair-list detail" in namespace "s" should contain "sr-mpls"

  Scenario: Source reaches the destination over the primary path
    Given the test topology exists
    # s -> d primary is s-n1-d (cost 2).
    Then ping from "s" to "10.0.0.8" should succeed
    And ping from "d" to "10.0.0.1" should succeed

  Scenario: Fast-reroute survives the primary link failure (s-n1)
    Given the test topology exists
    Then ping from "s" to "10.0.0.8" should succeed
    When I make namespace "s" interface "s-n1" down
    And I wait 5 seconds
    # d's loopback was TI-LFA-protected: the pre-installed backup
    # tunnels via n2 with [Node-SID(r1) 16500, Adj-SID(r1-r2),
    # Adj-SID(r2-r3)], avoiding the protected vertex n1 entirely
    # (s-n2-r1-r2-r3-d); reconvergence then settles on s-n2-r1-n1-d.
    # Either way the egress differs from the failed s-n1.
    Then ping from "s" to "10.0.0.8" should succeed
    When I make namespace "s" interface "s-n1" up
    And I wait 30 seconds
    # Primary restored once the adjacency re-forms.
    Then ping from "s" to "10.0.0.8" should succeed

  Scenario: TI-LFA compute-mode aggressive computes the same repair in parallel
    Given the test topology exists
    # Switch the TI-LFA scheduler to the parallel map-reduce mode
    # (docs/design/isis-tilfa-parallel-spf.md §13 for the OSPF
    # specifics). The config handler re-runs SPF on its own; results
    # are identical across modes — only the CPU scheduling differs.
    When I apply command "set router ospf fast-reroute ti-lfa compute-mode aggressive" in namespace "s"
    And I wait 5 seconds
    # The repair list is still computed after the parallel run...
    Then show command "show ospf ti-lfa" in namespace "s" should contain "Node-SID"
    # ...and the telemetry proves the aggressive scheduler ran it.
    And show command "show ospf" in namespace "s" should contain "mode=aggressive"

  Scenario: TI-LFA compute-mode sharding bounds parallelism and still protects
    Given the test topology exists
    # The shard count now nests under the `sharding` mode: one command
    # selects sharding and bounds parallelism to 2 shards.
    When I apply command "set router ospf fast-reroute ti-lfa compute-mode sharding shards 2" in namespace "s"
    And I wait 5 seconds
    Then show command "show ospf ti-lfa" in namespace "s" should contain "Node-SID"
    And show command "show ospf" in namespace "s" should contain "mode=sharding(2)"
    # The sharded recompute still protects for real: fail the primary
    # link and reach d over the repair / post-convergence path.
    When I make namespace "s" interface "s-n1" down
    And I wait 5 seconds
    Then ping from "s" to "10.0.0.8" should succeed
    When I make namespace "s" interface "s-n1" up
    And I wait 30 seconds
    Then ping from "s" to "10.0.0.8" should succeed
    # Deleting the `sharding` presence container resets the scheduler to
    # the stock serial mode (mode → serial, shards → 8) for the
    # remaining scenarios.
    When I apply command "delete router ospf fast-reroute ti-lfa compute-mode sharding" in namespace "s"
    And I wait 5 seconds
    Then show command "show ospf" in namespace "s" should contain "mode=serial"

  Scenario: Promoted backup actually forwards over the SR-MPLS repair
    Given the test topology exists
    # `backup-as-primary` swaps the metric-sort offset so each TI-LFA
    # repair installs as the active route and the SPF primary demotes
    # to metric+1; the toggle re-runs SPF itself. Traffic is pinned
    # onto the repair label stack while every link stays up — proving
    # the repair tunnel genuinely forwards, which the link-failure
    # scenario cannot (by ping time SPF has already reconverged onto a
    # plain post-convergence primary). Must run before the s-nofrr /
    # s-nosr scenarios strip the repair machinery from s.
    When I apply command "set router ospf fast-reroute backup-as-primary" in namespace "s"
    And I wait 5 seconds
    # d's loopback route now has the label-stack repair as its best
    # kernel entry, out the repair egress s-n2.
    Then kernel route "10.0.0.8" in namespace "s" should eventually contain "encap mpls"
    And kernel route "10.0.0.8" in namespace "s" should eventually contain "dev s-n2 proto ospf metric 2"
    # End-to-end over the repair: dies if any label hop on the repair
    # path fails to swap/pop/forward.
    And ping from "s" to "10.0.0.8" should succeed
    # Restore install-side ordering for the scenarios that follow.
    When I apply command "delete router ospf fast-reroute backup-as-primary" in namespace "s"
    And I wait 5 seconds
    Then ping from "s" to "10.0.0.8" should succeed

  Scenario: Disabling fast-reroute clears the repair-list
    Given the test topology exists
    # s still holds TI-LFA backups from the previous scenarios.
    Then show command "show ospf repair-list" in namespace "s" should contain "16500"
    # Re-apply s without `fast-reroute ti-lfa` (SR-MPLS stays on).
    When I apply config "s-nofrr.yaml" to namespace "s"
    And I wait 5 seconds
    # The toggle re-runs SPF without the TI-LFA pass: no graph repairs,
    # no installed backups — while the SR labels stay in the LFIB.
    Then show command "show ospf ti-lfa" in namespace "s" should contain "(no TI-LFA repair paths computed)"
    And show command "show ospf repair-list" in namespace "s" should contain "(no TI-LFA repair-list entries)"
    And mpls ilm in namespace "s" should contain label 16800

  Scenario: Deleting segment-routing mpls clears all MPLS ILM entries
    Given the test topology exists
    # s still has remote node-SID labels installed (r1 SID 500 -> 16500,
    # d SID 800 -> 16800).
    Then mpls ilm in namespace "s" should contain label 16500
    And mpls ilm in namespace "s" should contain label 16800
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
