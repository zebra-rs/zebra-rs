@ecmp_bfd_evict
@isis
@bfd
Feature: ECMP leg eviction on BFD failure
  As a network operator
  I want a BFD-detected failure of one ECMP leg (the link stays up,
  so the kernel cannot see it) to evict that leg from the kernel
  nexthop groups in one atomic replace per group, BEFORE SPF
  reconvergence rewrites the routes — phase 5 of
  docs/design/nexthop-protect-kernel-failover.md.

  TI-LFA deliberately computes no repair for SPF-level ECMP
  destinations: the surviving legs ARE the protection. This feature
  proves that holds for the link-up failure class too — without the
  eviction, the kernel would keep hashing flows onto the dead leg
  until SPF finishes.

  Like the switchover, the eviction is observable only in the daemon
  log ("evicted failed leg from N ECMP group(s)" is emitted ONLY when
  at least one group shrank): SPF supersedes its kernel state within
  milliseconds, by design.

  Test Topology (diamond, all metrics 1 — s reaches d ECMP via a and b):
  ```
        s (10.0.0.1)
       / \
     s-a  s-b          BFD runs on the s<->a leg only.
     /      \
    a        b
     \      /
     a-d  b-d
       \ /
        d (10.0.0.4)
  ```

  Scenario: Build the diamond and confirm ECMP, BFD, and reachability
    Given a clean test environment
    When I create namespace "s"
    And I create namespace "a"
    And I create namespace "b"
    And I create namespace "d"
    And I connect namespace "s" interface "s-a" to namespace "a" interface "a-s"
    And I connect namespace "s" interface "s-b" to namespace "b" interface "b-s"
    And I connect namespace "a" interface "a-d" to namespace "d" interface "d-a"
    And I connect namespace "b" interface "b-d" to namespace "d" interface "d-b"
    And I start zebra-rs in namespace "s"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "d"
    And I apply config "s.yaml" to namespace "s"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "d.yaml" to namespace "d"
    And I wait 10 seconds
    # d's loopback is ECMP across both legs in the kernel.
    Then kernel route "10.0.0.4" in namespace "s" should eventually contain "dev s-a"
    And kernel route "10.0.0.4" in namespace "s" should eventually contain "dev s-b"
    And bfd session in namespace "s" on interface "s-a" should be up
    And ping from "s" to "10.0.0.4" should succeed

  Scenario: BFD-down on one leg evicts it from the kernel ECMP group
    Given the test topology exists
    Then ping from "s" to "10.0.0.4" should succeed
    # Kill BFD only: the link stays up (no autonomous kernel flush) and
    # IIHs keep flowing — s must learn of the dead leg from BFD and
    # shrink the ECMP membership itself.
    When I drop bfd control packets in namespace "s"
    Then bfd session in namespace "s" on interface "s-a" should be down
    # The eviction fired: at least one ECMP group shrank (this exact
    # line is only logged when N > 0).
    And daemon log in namespace "s" should eventually contain "evicted failed leg from"
    And daemon log in namespace "s" should eventually contain "ECMP group(s)"
    # SPF reconvergence then drops the a-plane entirely; forwarding
    # stays healthy on the surviving leg throughout.
    And kernel route "10.0.0.4" in namespace "s" should eventually contain "dev s-b"
    And ping from "s" to "10.0.0.4" should succeed
    # Recovery: BFD re-establishes, the adjacency re-forms, and the
    # evicted leg returns to the ECMP set (exercises the drain-and-
    # recreate lifecycle of the marked-invalid member group).
    When I restore bfd control packets in namespace "s"
    And I wait 15 seconds
    Then bfd session in namespace "s" on interface "s-a" should be up
    And kernel route "10.0.0.4" in namespace "s" should eventually contain "dev s-a"
    And ping from "s" to "10.0.0.4" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "s"
    And I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "d"
    And I delete namespace "s"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "d"
    Then the test environment should be clean
