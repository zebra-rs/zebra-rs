@ospf_ecmp_bfd_evict
@ospf
@bfd
Feature: ECMP leg eviction and restore on BFD failure (OSPFv2)
  As a network operator
  I want a BFD-detected failure of one ECMP leg to evict that leg from
  the kernel nexthop groups, and the leg to come BACK when BFD
  recovers — the OSPFv2 sibling of ecmp_bfd_evict.feature.

  The eviction half is shared with IS-IS: `protect_switch` shrinks each
  affected kernel group in one atomic replace. The restore half is not.
  OSPF's BFD-down handler unsubscribes the session and ignores every
  transition that is not to Down, so there is no BFD "up" event to react
  to; recovery instead arrives as the adjacency re-forming from hellos
  and re-arming BFD in `bfd_reconcile_nbr`.

  Without a restore there, the group stays shrunk whenever reconvergence
  does not rewrite the affected prefixes — which is exactly what happens
  when the adjacency returns before SPF ran. The failure is silent and
  asymmetric, and this feature is written to catch precisely that: the
  RIB keeps reporting both legs while the kernel forwards over one, so
  asserting on `show ip route` alone would pass. The kernel route is the
  assertion that matters.

  Test Topology (diamond, all costs 1 — s reaches d ECMP via a and b):
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

  Scenario: BFD-down evicts the leg, and BFD-up brings it back
    Given the test topology exists
    Then ping from "s" to "10.0.0.4" should succeed
    # Kill BFD only: the link stays up, so s must learn of the dead leg
    # from BFD and shrink the ECMP membership itself.
    When I drop bfd control packets in namespace "s"
    Then bfd session in namespace "s" on interface "s-a" should be down
    # The eviction fired: at least one ECMP group shrank (this exact
    # line is only logged when N > 0).
    And daemon log in namespace "s" should eventually contain "evicted failed leg from"
    And daemon log in namespace "s" should eventually contain "ECMP group(s)"
    And kernel route "10.0.0.4" in namespace "s" should eventually contain "dev s-b"
    And ping from "s" to "10.0.0.4" should succeed
    # Recovery. The evicted leg must return to the kernel ECMP set — the
    # regression this feature exists for leaves it out indefinitely,
    # because nothing tells the RIB the adjacency is usable again.
    When I restore bfd control packets in namespace "s"
    And I wait 15 seconds
    Then bfd session in namespace "s" on interface "s-a" should be up
    And kernel route "10.0.0.4" in namespace "s" should eventually contain "dev s-a"
    And kernel route "10.0.0.4" in namespace "s" should eventually contain "dev s-b"
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
