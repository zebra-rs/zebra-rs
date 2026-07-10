@isis_srmpls
@isis
Feature: IS-IS SR-MPLS static-route recursive nexthop tracking with TI-LFA
  As a network operator
  I want a static route whose nexthop is a remote loopback (s:
  172.168.1.0/24 via 10.0.0.8) to resolve recursively through the
  IS-IS SR-MPLS route to that loopback — inheriting its transport
  label stack — and to follow the underlay whenever IS-IS changes the
  installed path, including a TI-LFA `backup-as-primary` promotion
  that swaps the active nexthop of the covering `Protect` route.

  End hosts e1 (behind s) and e2 (behind d) carry only static default
  routes; an e1 -> e2 ping traverses the SR-MPLS core end-to-end and
  dies if any label hop fails to push/swap/pop, so it pins every
  static-resolution assertion to real forwarding.

  All links are point-to-point veth pairs; every core router is
  is-type level-2-only with `segment-routing mpls`. Prefix-SIDs index
  100..800 resolve against the RIB's default SRGB (base 16000): s's
  node SID is label 16100, n1's 16200, r1's 16500, d's 16800.
  `fast-reroute ti-lfa` is deliberately NOT in the startup configs —
  it is enabled at runtime mid-feature.

  The metrics are tuned so a plain loop-free alternate for the s-n1
  link is impossible: n2's shortest path to d (n2-r1-n1-d, cost 3)
  ties n2-s-n1-d, so protecting s-n1 needs an SR repair tunnel — P
  node r1 (node SID 16500) followed by adjacency SIDs r1->n1 and
  n1->d. Adjacency-SID values come from a first-fit SRLB pool (base
  15000) keyed on Hello arrival order, so scenarios assert only the
  deterministic node-SID labels, never adjacency-SID digits.

  Test Topology (metric shown where != 1; loopback 10.0.0.X / SID X00):
  ```
   e1 --- s (10.0.0.1)
       1 / 1 \      \ 1000
        n1    n2     n3
    1 / |1 \1  \1     \1000
 d ─┘ 1 |   \    \      \
(10.0.0.8)   \1000\      \
    1 \ |     r1───────── (r1-n3 1000)
       r2    /  \1000
    1000\   /1   \(r1-r2 1000)
         r2 ──────┘
           \1000
            r3 (r3-d 1)   d --- e2
    s-n1 1  s-n2 1  s-n3 1000   n1-r1 1  n2-r1 1  n3-r1 1000
    n1-r2 1 r1-r2 1000 r2-r3 1000  n1-d 1  r3-d 1
  ```

  Scenario: Build the SR-MPLS topology with e1/e2 hosts and confirm adjacencies
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
    And I start zebra-rs in namespace "e1"
    And I start zebra-rs in namespace "e2"
    And I start zebra-rs in namespace "s"
    And I start zebra-rs in namespace "n1"
    And I start zebra-rs in namespace "n2"
    And I start zebra-rs in namespace "n3"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I start zebra-rs in namespace "d"
    And I apply config "e1.yaml" to namespace "e1"
    And I apply config "e2.yaml" to namespace "e2"
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
    Then ping from "s" to "192.168.10.2" should succeed
    And ping from "s" to "10.0.0.2" should succeed
    # The e1/e2 hosts reach their first-hop routers.
    And ping from "e1" to "172.168.0.2" should succeed
    And ping from "e2" to "172.168.1.1" should succeed

  Scenario: Static route resolves recursively through the SR-MPLS underlay
    Given the test topology exists
    # s's IS-IS route to d's loopback carries d's node-SID label.
    Then show command "show ip route prefix 10.0.0.8/32" in namespace "s" should eventually contain "[115/12] via 192.168.10.2, s-n1, label 16800"
    # The static 172.168.1.0/24 via 10.0.0.8 is not on-link: NHT
    # resolves the gateway through that IS-IS route and inherits its
    # transport label — rendered FRR-style as a recursive two-liner.
    And show command "show ip route prefix 172.168.1.0/24" in namespace "s" should eventually contain "via 10.0.0.8 (recursive)"
    And show command "show ip route prefix 172.168.1.0/24" in namespace "s" should contain "via 192.168.10.2, s-n1, label 16800"
    # The kernel forwards the static prefix with the inherited label
    # push toward n1 — the proof the resolution reached the FIB.
    And kernel route "172.168.1.0/24" in namespace "s" should eventually contain "encap mpls"
    And kernel route "172.168.1.0/24" in namespace "s" should eventually contain "16800"
    And kernel route "172.168.1.0/24" in namespace "s" should eventually contain "via 192.168.10.2"
    # End-to-end: e1 -> s (label 16800 push) -> n1 (PHP) -> d -> e2,
    # return over d's mirrored static (label 16100 toward s).
    And ping from "e1" to "172.168.1.2" should succeed

  Scenario: Runtime TI-LFA enable computes a repair without moving the static
    Given the test topology exists
    # Enable TI-LFA on s at runtime — the config callback re-runs SPF
    # itself, no `clear isis spf` needed.
    When I apply command "set router isis fast-reroute ti-lfa" in namespace "s"
    And I wait 5 seconds
    # The s-n1-protected routes now carry a pre-computed repair via
    # n2 (the P node r1's node SID 16500 + adjacency SIDs).
    Then show command "show isis route detail" in namespace "s" should contain "Backup path: TI-LFA, via 192.168.3.2"
    # d's loopback route: primary unchanged, repair standby at
    # metric+1 out s-n2.
    And show command "show ip route prefix 10.0.0.8/32" in namespace "s" should contain "[115/12] via 192.168.10.2, s-n1, label 16800"
    And show command "show ip route prefix 10.0.0.8/32" in namespace "s" should contain "[115/13] via 192.168.3.2, s-n2, label 16500"
    # Negative control: a standby repair must NOT move the static —
    # NHT resolves through the active (primary) member only.
    And kernel route "172.168.1.0/24" in namespace "s" should eventually contain "16800"
    And kernel route "172.168.1.0/24" in namespace "s" should eventually contain "via 192.168.10.2"

  Scenario: backup-as-primary promotes the repair to the active route
    Given the test topology exists
    # `backup-as-primary` swaps the metric-sort offset so the TI-LFA
    # repair installs as the active route at the SPF metric and the
    # SPF primary demotes to metric+1. The config callback re-runs
    # SPF on its own.
    When I apply command "set router isis fast-reroute backup-as-primary" in namespace "s"
    And I wait 5 seconds
    # d's loopback now forwards over the repair label stack.
    Then show command "show ip route prefix 10.0.0.8/32" in namespace "s" should eventually contain "[115/12] via 192.168.3.2, s-n2, label 16500"
    And kernel route "10.0.0.8" in namespace "s" should eventually contain "dev s-n2 proto isis metric 12"
    And kernel route "10.0.0.8" in namespace "s" should eventually contain "16500/"

  Scenario: Static nexthop tracking follows the promoted repair
    Given the test topology exists
    # The IS-IS Protect route for 10.0.0.8/32 changed its active
    # member; the debounced static re-resolve must notice, re-inherit
    # the repair's label stack, and re-push the kernel route — this
    # was the bug: the in-memory RIB updated but the kernel kept
    # forwarding via the demoted path.
    Then kernel route "172.168.1.0/24" in namespace "s" should eventually contain "16500/"
    And kernel route "172.168.1.0/24" in namespace "s" should eventually contain "via 192.168.3.2"
    And show command "show ip route prefix 172.168.1.0/24" in namespace "s" should contain "via 10.0.0.8 (recursive)"
    And show command "show ip route prefix 172.168.1.0/24" in namespace "s" should contain "via 192.168.3.2, s-n2, label 16500"
    # End-to-end over the promoted repair: e1 -> s (push 16500/adj/adj)
    # -> n2 -> r1 -> n1 -> d -> e2. Dies if any hop mis-forwards.
    And ping from "e1" to "172.168.1.2" should succeed

  Scenario: Reverting backup-as-primary moves the static back
    Given the test topology exists
    When I apply command "delete router isis fast-reroute backup-as-primary" in namespace "s"
    And I wait 5 seconds
    # The SPF primary is active again and the static follows it back.
    Then kernel route "172.168.1.0/24" in namespace "s" should eventually contain "16800"
    And kernel route "172.168.1.0/24" in namespace "s" should eventually contain "via 192.168.10.2"
    And ping from "e1" to "172.168.1.2" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "e1"
    And I stop zebra-rs in namespace "e2"
    And I stop zebra-rs in namespace "s"
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
