@serial
@ospfv3_bfd_frr
Feature: OSPFv3 TI-LFA kernel-side fast-reroute on BFD failure
  As a network operator
  I want a BFD-detected primary failure (the link stays up, so the
  kernel cannot see it) to rewire the pre-installed protection
  indirection groups onto their TI-LFA repairs in one atomic kernel
  operation per failed adjacency, BEFORE SPF reconvergence rewrites
  the routes — phase 4 of docs/design/nexthop-protect-kernel-failover.md,
  the OSPFv3 sibling of isis_tilfa_bfd.feature.

  The topology is the ospfv3_tilfa SR-MPLS ring with BFD
  enabled on the protected s<->n1 adjacency. BFD-down is induced by
  dropping inbound UDP/3784 in namespace s: the veth link stays up and
  hellos keep flowing, so the teardown is provably BFD's doing — the
  failure class the kernel's autonomous link-down flush cannot cover.
  The switchover is observable only in the daemon log ("rewired N
  protection group(s) onto repairs" is emitted ONLY when at least one
  group moved): its kernel state is superseded within milliseconds by
  the post-convergence SPF routes, by design.

  Scenario: Build the topology and confirm adjacency, BFD, and repairs
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
    # Gate on full convergence (SPF + SR labels + install) before the
    # single-shot show asserts — the kernel-route step polls.
    Then kernel route "2001:db8::8" in namespace "s" should eventually contain "proto ospf"
    And bfd session in namespace "s" on interface "s-n1" should be up
    And show command "show ospfv3 ti-lfa" in namespace "s" should contain "Adj-SID"
    And ping from "s" to "2001:db8::8" should succeed
    And ping from "d" to "2001:db8::1" should succeed

  Scenario: BFD-down with the link up triggers the kernel-side switchover
    Given the test topology exists
    Then ping from "s" to "2001:db8::8" should succeed
    # Kill BFD only: the link stays up (no autonomous kernel flush) and
    # hellos keep flowing (no dead-timer expiry for ~40s) — s must learn
    # of the failure from BFD and bridge traffic onto the repairs.
    When I drop bfd control packets in namespace "s"
    Then bfd session in namespace "s" on interface "s-n1" should be down
    # The switchover fired: at least one protection group was rewired
    # onto its repair (this exact line is only logged when N > 0).
    And daemon log in namespace "s" should eventually contain "rewired"
    And daemon log in namespace "s" should eventually contain "protection group(s) onto repairs"
    # SPF reconvergence then re-routes around n1 entirely.
    And kernel route "2001:db8::8" in namespace "s" should eventually contain "dev s-n2"
    # "eventually": the rewired route may still be resolving ND on the
    # repair path when the first probe fires under host load.
    And ping from "s" to "2001:db8::8" should eventually succeed
    # Recovery: BFD re-establishes and the primary path returns.
    When I restore bfd control packets in namespace "s"
    And I wait 15 seconds
    Then bfd session in namespace "s" on interface "s-n1" should be up
    And kernel route "2001:db8::8" in namespace "s" should eventually contain "dev s-n1"
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
