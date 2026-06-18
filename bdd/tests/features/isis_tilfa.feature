@isis_tilfa
@isis
Feature: IS-IS TI-LFA fast-reroute over SR-MPLS
  As a network operator
  I want eight zebra-rs instances running IS-IS Level-2 with SR-MPLS and
  TI-LFA (RFC 9490) to pre-compute a topology-independent loop-free
  repair for the source's primary path, so that when the primary link
  fails the source still reaches the destination over the SR repair /
  post-convergence path.

  All links are point-to-point veth pairs; every router is is-type
  level-2-only with `segment-routing mpls` and `fast-reroute ti-lfa`.
  Prefix-SIDs index 100..800 resolve against the RIB's default SRGB
  (base 16000), so node s's SID is label 16100, d's is 16800, etc.

  The metrics are tuned so a simple LFA is impossible: s reaches d via
  s-n1 (cost 2); the only other neighbours (n2, n3) are equidistant /
  expensive, so protecting the s-n1 link requires an SR repair tunnel
  through the r-plane rather than a plain loop-free alternate.

  Test Topology (metric shown where != 1; loopback 10.0.0.X / SID X00):
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

  Scenario: Build the TI-LFA topology and confirm adjacencies + SR
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
    And I wait 10 seconds
    # Directly-connected adjacency over s-n1, then n1's loopback over SR.
    Then ping from "s" to "192.168.0.2" should succeed
    And ping from "s" to "10.0.0.2" should succeed

  Scenario: SR-MPLS labels and a TI-LFA repair are installed on the source
    Given the test topology exists
    # Prefix-SIDs resolved to labels (SR active), and the s-n1-protected
    # routes carry a pre-computed TI-LFA repair tunnel.
    Then show command "show isis route detail" in namespace "s" should contain "Prefix-SID:"
    And show command "show isis route detail" in namespace "s" should contain "Backup path: TI-LFA"

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
    # Reachability restored over the SR repair / post-convergence path
    # (s-n2-r1-n1-d), out a different interface than the failed s-n1.
    Then ping from "s" to "10.0.0.8" should succeed
    When I make namespace "s" interface "s-n1" up
    And I wait 10 seconds
    # Primary restored.
    Then ping from "s" to "10.0.0.8" should succeed

  Scenario: TI-LFA compute-mode aggressive computes the same repair in parallel
    Given the test topology exists
    # Switch the TI-LFA scheduler to the parallel map-reduce mode
    # (docs/design/isis-tilfa-parallel-spf.md). The config handler
    # re-runs SPF on its own; results are identical across modes by
    # design — only the CPU scheduling differs.
    When I apply command "set router isis fast-reroute ti-lfa compute-mode aggressive" in namespace "s"
    And I wait 5 seconds
    # The repair tunnel is still computed after the parallel run...
    Then show command "show isis route detail" in namespace "s" should contain "Backup path: TI-LFA"
    # ...and the SPF telemetry proves the aggressive scheduler ran it
    # (q = one reverse SPF per protected destination, pc deduped per
    # protected first-hop node).
    And show command "show isis spf" in namespace "s" should contain "mode=aggressive"

  Scenario: TI-LFA compute-mode sharding bounds parallelism and still protects
    Given the test topology exists
    # The shard count now nests under the `sharding` mode: one command
    # selects sharding and bounds parallelism to 2 shards.
    When I apply command "set router isis fast-reroute ti-lfa compute-mode sharding shards 2" in namespace "s"
    And I wait 5 seconds
    Then show command "show isis route detail" in namespace "s" should contain "Backup path: TI-LFA"
    And show command "show isis spf" in namespace "s" should contain "mode=sharding(2)"
    # The sharded recompute still protects for real: fail the primary
    # link and reach d over the repair / post-convergence path.
    When I make namespace "s" interface "s-n1" down
    And I wait 5 seconds
    Then ping from "s" to "10.0.0.8" should succeed
    When I make namespace "s" interface "s-n1" up
    And I wait 10 seconds
    Then ping from "s" to "10.0.0.8" should succeed
    # A surgical runtime delete of the `sharding` presence container
    # exercises the handler's reset-to-default path (mode → serial,
    # shards → 8); the next full-file apply would wipe these leaves
    # anyway (file applies are whole-config replaces).
    When I apply command "delete router isis fast-reroute ti-lfa compute-mode sharding" in namespace "s"
    And I wait 5 seconds
    Then show command "show isis spf" in namespace "s" should contain "mode=serial"

  Scenario: no-php sets the P (no-PHP) flag and makes the penultimate hop swap
    Given the test topology exists
    # By default s advertises its loopback Prefix-SID (10.0.0.1/32, SID
    # 100) with PHP in effect, so the P flag is clear everywhere in the
    # LSDB — neither Prefix-SID nor Adjacency-SID renders "P:1".
    Then show command "show isis database detail" in namespace "s" should not contain "P:1"
    # n1 is the penultimate hop to s's loopback (label 16100); with PHP it
    # pops the node-SID label before delivering to s.
    And mpls ilm outgoing label for label 16100 in namespace "n1" should be "Pop"
    # Re-apply s with `no-php` under the loopback's prefix-sid.
    When I apply config "s-nophp.yaml" to namespace "s"
    # 10s, not the usual 5s: the LSP-generation throttle (IOS-XR-style
    # backoff, 5000ms secondary/maximum) can delay s's re-origination by
    # up to ~5s, then the change still has to flood to n1 and drive n1's
    # SPF + ILM rebuild. 5s lands right on that edge and flakes.
    And I wait 10 seconds
    # Changing no-php re-originates s's self-LSP with the P (no-PHP) flag
    # set on its loopback Prefix-SID, so the flag now shows in the LSDB.
    Then show command "show isis database detail" in namespace "s" should contain "P:1"
    # And n1 now keeps the label (swap 16100 -> 16100) instead of popping,
    # so s receives the labeled packet intact.
    And mpls ilm outgoing label for label 16100 in namespace "n1" should be "16100"

  Scenario: no-local-prefix-sid suppresses only the local Prefix-SID in the LFIB
    Given the test topology exists
    # By default s installs its own node-SID label (SID 100 -> 16100) as a
    # local pop entry, alongside remote node-SIDs (e.g. d's SID 800 -> 16800).
    Then mpls ilm in namespace "s" should contain label 16100
    And mpls ilm in namespace "s" should contain label 16800
    # Re-apply s with `no-local-prefix-sid` under segment-routing mpls.
    When I apply config "s-nolocal.yaml" to namespace "s"
    And I wait 5 seconds
    # The local label is withdrawn from the LFIB; the remote one stays.
    Then mpls ilm in namespace "s" should not contain label 16100
    And mpls ilm in namespace "s" should contain label 16800

  Scenario: Deleting segment-routing mpls clears all MPLS ILM entries
    Given the test topology exists
    # s still has remote node-SID labels installed (n1 SID 200 -> 16200,
    # d SID 800 -> 16800).
    Then mpls ilm in namespace "s" should contain label 16200
    And mpls ilm in namespace "s" should contain label 16800
    # Remove `segment-routing mpls` from s entirely.
    When I apply config "s-nosr.yaml" to namespace "s"
    And I wait 5 seconds
    # Disabling SR-MPLS must withdraw every MPLS ILM entry — prefix-SIDs
    # and adjacency-SIDs — leaving the LFIB completely empty.
    Then mpls ilm in namespace "s" should be empty

  Scenario: lsp-mtu above the link MTU is flagged on the source's interfaces
    Given the test topology exists
    # s's point-to-point links are veth pairs with the default 1500-byte
    # MTU. s-lspmtu.yaml raises lsp-mtu to 9000, so an LSP at that size
    # can't fit a single frame on s-n1/s-n2/s-n3; the flood path drops it
    # (logged at warning level) and show flags each link.
    When I apply config "s-lspmtu.yaml" to namespace "s"
    And I wait 15 seconds
    Then show command "show isis interface detail" in namespace "s" should contain "exceeds interface MTU"

  Scenario: lsp-mtu above the link MTU drops s's LSP so n1 never learns the new prefix
    Given the test topology exists
    # s-lspmtu.yaml advertises 100.99.0.1/32, but with lsp-mtu over the
    # link MTU s's LSP is dropped on every link, so n1 never receives it.
    Then show command "show isis route" in namespace "n1" should not contain "100.99.0.1/32"

  Scenario: Lowering lsp-mtu under the link MTU lets s's LSP flood to n1
    Given the test topology exists
    When I apply config "s-lspmtu-ok.yaml" to namespace "s"
    And I wait 20 seconds
    # lsp-mtu 1400 < 1500, so the flood path no longer drops s's LSP: the
    # interfaces are no longer flagged and n1 installs the previously-
    # dropped network, proving the drop was the over-MTU lsp-mtu.
    Then show command "show isis interface detail" in namespace "s" should not contain "exceeds interface MTU"
    And show command "show isis route" in namespace "n1" should contain "100.99.0.1/32"

  Scenario: Promoted backup actually forwards over the SR-MPLS repair
    Given the test topology exists
    # `backup-as-primary` swaps the metric-sort offset so each TI-LFA
    # repair installs as the active route and the SPF primary demotes
    # to metric+1; `clear isis spf` recomputes and reinstalls with the
    # flag applied. Traffic is pinned onto the repair label stack while
    # every link stays up — proving the repair genuinely forwards,
    # which the link-failure scenario cannot (by ping time SPF has
    # already reconverged onto a plain post-convergence primary).
    # s is running s-lspmtu-ok.yaml here, which keeps segment-routing
    # mpls + fast-reroute ti-lfa, so the repair is still computed.
    When I apply command "set router isis fast-reroute backup-as-primary" in namespace "s"
    And I run "clear isis spf" in namespace "s"
    # d's loopback route now has the label-stack repair as its best
    # kernel entry: out the repair egress s-n2 at metric 12 (2 path +
    # 10 for d's loopback prefix), demoted plain primary behind at 13.
    Then kernel route "10.0.0.8" in namespace "s" should eventually contain "encap mpls"
    And kernel route "10.0.0.8" in namespace "s" should eventually contain "dev s-n2 proto isis metric 12"
    # End-to-end over the repair: dies if any label hop on the repair
    # path fails to swap/pop/forward.
    And ping from "s" to "10.0.0.8" should succeed

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
