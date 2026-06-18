@flexalgo_tilfa_srv6
Feature: IS-IS per-Flex-Algorithm TI-LFA over SRv6
  Flex-Algo sibling of @tilfa_srv6. Same proven eight-router topology and
  metrics (IPv6-only, every circuit point-to-point), but each router also
  runs a Flexible-Algorithm 128 (RFC 9350) on the SRv6 dataplane:

  - each router owns a per-algo SRv6 locator fcbb:bbbb:1X::/48 (behavior
    usid) bound to algo 128 via `segment-routing srv6 flex-algo-locator`,
    alongside its base (algo-0) locator fcbb:bbbb:X::/48;
  - algo 128 has no affinity constraints, so its topology equals algo 0's
    — the per-algo TI-LFA repair therefore mirrors the algo-0 one;
  - `flex-algo 128 fast-reroute ti-lfa` enables per-algo TI-LFA, so the
    per-algo locator routes carry a repair resolved to *algo-128* End /
    End.X SIDs (the repair stays inside algo 128's topology), SRH-inserted
    like the algo-0 repair.

  The metrics are tuned (from @tilfa_srv6) so a simple LFA is impossible:
  s reaches d via s-n1 (cost 2); protecting s-n1 needs an SR repair tunnel
  through the r-plane. This validates per-algo TI-LFA + per-algo End.X SID
  origination end-to-end on the SRv6 dataplane.

  NOTE: like every BDD here this runs under the (CI-excluded) bdd suite in
  network namespaces; it has not been executed in the authoring sandbox.

  Scenario: Build the per-Flex-Algo SRv6 TI-LFA topology and confirm IS-IS
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
    And I wait 20 seconds
    # Directly-connected adjacency over s-n1, then loopbacks across the
    # IS-IS IPv6 (algo-0) domain.
    Then ping from "s" to "2001:db8:0:1::2" should succeed
    And ping from "s" to "2001:db8::8" should succeed
    And ping from "d" to "2001:db8::1" should succeed

  Scenario: Per-algo SRv6 SIDs exist and algo-128 locators are reachable
    Given the test topology exists
    # s owns its base + algo-128 End (uN) SIDs and carved End.X (uA) SIDs
    # per adjacency for both algorithms; each uA also installs its LIB
    # twin for NEXT-C-SID carrier resolution.
    Then show command "show segment-routing srv6 sid" in namespace "s" should contain "uN"
    And show command "show segment-routing srv6 sid" in namespace "s" should contain "uA"
    And show command "show segment-routing srv6 sid" in namespace "s" should contain "uA(LIB)"
    # s reaches every other node's algo-128 locator over the algo-128
    # topology (= algo-0 here): d (fcbb:bbbb:18::), n1 (fcbb:bbbb:12::),
    # r3 (fcbb:bbbb:17::).
    And show command "show isis flex-algo route algorithm 128" in namespace "s" should contain "fcbb:bbbb:18::"
    And show command "show isis flex-algo route algorithm 128" in namespace "s" should contain "fcbb:bbbb:12::"
    And show command "show isis flex-algo route algorithm 128" in namespace "s" should contain "fcbb:bbbb:17::"

  Scenario: Algo-0 fast-reroute survives the primary link failure (s-n1)
    Given the test topology exists
    Then ping from "s" to "2001:db8::8" should succeed
    When I make namespace "s" interface "s-n1" down
    And I wait 5 seconds
    # Reachability restored over the SRv6 repair / post-convergence path
    # (out a different interface than the failed s-n1). The algo-128
    # locator route to d also reconverges and stays installed.
    Then ping from "s" to "2001:db8::8" should succeed
    And kernel route "fcbb:bbbb:18::/48" in namespace "s" should eventually contain "proto isis"
    When I make namespace "s" interface "s-n1" up
    And I wait 10 seconds
    Then ping from "s" to "2001:db8::8" should succeed

  Scenario: Promoted per-algo backup forwards over the algo-128 SRv6 repair
    Given the test topology exists
    # `backup-as-primary` swaps the metric-sort offset so each TI-LFA
    # repair (algo-0 and per-algo) installs as the active route; `clear
    # isis spf` recomputes and reinstalls with the flag applied. This
    # pins the algo-128 locator route onto its SRv6 repair while every
    # link stays up — proving the algo-128 uN/uA SID list genuinely
    # installs in the dataplane.
    When I apply command "set router isis fast-reroute backup-as-primary" in namespace "s"
    And I run "clear isis spf" in namespace "s"
    # d's algo-128 locator route now has the SRH-insert repair as its best
    # kernel entry: out the repair egress s-n2, an IS-IS route.
    Then kernel route "fcbb:bbbb:18::/48" in namespace "s" should eventually contain "mode inline"
    And kernel route "fcbb:bbbb:18::/48" in namespace "s" should eventually contain "proto isis"
    And kernel route "fcbb:bbbb:18::/48" in namespace "s" should eventually contain "dev s-n2"
    # NEXT-C-SID compression: the algo-128 repair uSIDs (uN of the P node
    # plus the uAs) ride one 128-bit carrier, so the inserted SRH is
    # carrier + original destination — 2 segments.
    And kernel route "fcbb:bbbb:18::/48" in namespace "s" should eventually contain "segs 2 ["
    # Algo-0 forwarding stays intact (same topology, separate locator).
    And ping from "s" to "2001:db8::8" should succeed

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
