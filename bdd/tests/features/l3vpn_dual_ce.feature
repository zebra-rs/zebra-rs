@serial
@l3vpn_dual_ce
Feature: Two BGP CE neighbors under a single VRF
  As a service provider attaching more than one customer edge to the
  same VRF on a PE
  I want every neighbor under `router bgp vrf <name>` to establish and
  carry routes, not just the first one
  So that a multi-CE VRF converges instead of silently wedging one
  session in Idle.

  Regression guard for issue #2077 / PR #2071. `materialize_peers`
  used to call `Peer::start()` *before* `PeerMap::insert_with_key`
  assigned the peer's stable ident. `start_timer!` captures
  `peer.ident` by value when it arms the idle-hold timer, and the
  per-VRF loop dispatches `Message::Event(ident, …)` purely on that
  value, so every peer past the first armed its timer under ident 0
  and its `Event::Start` was delivered to the *first* peer instead.

  The wedged peer stays in Idle, which blocks the session from both
  directions: it never dials, and `handle_peer_connection` drops
  inbound streams for an Idle peer, so the CE's own dial is refused
  too. Before the fix CE2 below never leaves Idle.

  Every pre-existing BDD config puts at most one neighbor under a
  `router bgp vrf` block (106 such blocks, zero with two), which is
  why nothing caught this. The second neighbor is the entire point of
  this topology.

  Test Topology (3 namespaces):
  ```
   ce1 ────────── pe1 ────────── ce2
   AS 65001    AS 65000        AS 65002
   lo          vrf-cust        lo
   10.0.1.1/32 RD 65000:1      10.0.2.1/32
        .2 ── .1        .1 ── .2
       10.1.0.0/30    10.2.0.0/30
  ```
  Both PE-CE sessions are eBGP and both live inside vrf-cust. There is
  no VPNv4 core: PE1 re-advertises each CE's prefixes to the other CE
  out of the same VRF Loc-RIB, so the CE-to-CE ping proves both
  sessions carry routes rather than merely reaching Established.

  Scenario: Build the dual-CE VRF topology
    Given a clean test environment
    When I create namespace "ce1"
    And I create namespace "pe1"
    And I create namespace "ce2"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I connect namespace "pe1" interface "ce2" to namespace "ce2" interface "pe1"
    And I start zebra-rs in namespace "ce1"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "ce2"
    And I apply config "ce1.yaml" to namespace "ce1"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "ce2.yaml" to namespace "ce2"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp vrf" in namespace "pe1" should contain "vrf-cust"
    And show command "show bgp vrf" in namespace "pe1" should contain "running"

  Scenario: Both PE-CE sessions in the VRF reach Established
    # The assertion that actually catches the regression. It is made
    # from the CE side deliberately: `BGP session in …` queries the
    # global instance, and each CE's peer *is* a global neighbor, so
    # this needs no per-VRF show plumbing to be trustworthy.
    #
    # CE1 is the control — it established even with the bug, because
    # the first peer's accidental ident 0 happened to be correct. CE2
    # is the regression guard.
    Given the test topology exists
    Then BGP session in "ce1" to "10.1.0.1" should eventually be "Established"
    And BGP session in "ce2" to "10.2.0.1" should eventually be "Established"

  Scenario: The VRF Loc-RIB holds both CE's prefixes
    # Proves the second session is not merely up but actually
    # exchanging NLRI into the shared VRF table.
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust" in namespace "pe1" should eventually contain "10.0.1.1/32"
    And show command "show bgp vrf vrf-cust" in namespace "pe1" should eventually contain "10.0.2.1/32"

  Scenario: CE-to-CE reachability across the shared VRF
    # End-to-end: PE1 re-advertises each CE's routes to the other CE
    # and forwards between them in vrf-cust's kernel table.
    #
    # Expect ~25-30s before the first reply, and don't "fix" that by
    # trimming the wait above: the CE-side `adv-interval ebgp 3` does
    # not apply to PE1's half of the session. Per-VRF peers are built
    # by `materialize_peers` from the `router bgp vrf` subtree, which
    # carries no timer plumbing at all, so they run the default 30s
    # eBGP MRAI on the PE-to-CE direction. The step's own budget
    # (60 attempts) covers it with room to spare.
    Given the test topology exists
    Then ping from "ce1" to "10.0.2.1" should eventually succeed
    And ping from "ce2" to "10.0.1.1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "ce2"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    And I delete namespace "ce2"
    Then the test environment should be clean
