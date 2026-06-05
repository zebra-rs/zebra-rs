@isis_bfd_ipv6_p2p
@bfd
Feature: IS-IS BFD over an IPv6-only point-to-point link
  As a network operator running IS-IS over IPv6-only links
  I want BFD to protect the point-to-point adjacency
  So that a forwarding failure tears the adjacency down well within the IS-IS
  hold time, and the adjacency stays down (RFC 5882 hold-down) until BFD
  recovers — even while IIHs keep arriving.

  The single-hop BFD session is built from the two ends' IPv6 link-local
  addresses (learned via TLV 232). Each scenario is self-contained (own setup
  and teardown) so the Echo scenarios configure echo-mode before the session
  first comes up (echo is armed at session establishment, not retrofitted).

  BFD-down is induced by dropping inbound UDP/3784 in one namespace: the link
  stays up and IIHs (L2 ISO PDUs, not IP/UDP) keep flowing, so a fast teardown
  is provably BFD's doing — not carrier loss, not the ~30s IS-IS hold timer.

  Test Topology (point-to-point veth):
  ```
   2001:db8:1::1/64                       2001:db8:1::2/64
        (i1)                                   (i1)
    ┌────┴────┐                            ┌────┴────┐
    │   z1    │────────── P2P ─────────────│   z2    │
    └─────────┘                            └─────────┘
  lo 2001:db8:0:ffff::1/128             lo 2001:db8:0:ffff::2/128
  ```

  Scenario: BFD without Echo protects the adjacency and tears it down on BFD failure
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-noecho.yaml" to namespace "z1"
    And I apply config "z2-noecho.yaml" to namespace "z2"
    And I wait 10 seconds
    Then isis neighbor in namespace "z1" at level 2 on interface "i1" should be up
    And bfd session in namespace "z1" on interface "i1" should be up
    And bfd session in namespace "z2" on interface "i1" should be up
    And ping from "z1" to "2001:db8:0:ffff::2" should succeed
    # BFD-down isolation: link stays up, IIHs keep flowing.
    When I drop bfd control packets in namespace "z2"
    Then bfd session in namespace "z1" on interface "i1" should be down
    And isis neighbor in namespace "z1" at level 2 on interface "i1" should not be up
    And ping from "z1" to "2001:db8:0:ffff::2" should fail
    # Recovery: BFD re-establishes and IS-IS lifts the hold-down.
    When I restore bfd control packets in namespace "z2"
    And I wait 20 seconds
    Then bfd session in namespace "z1" on interface "i1" should be up
    And isis neighbor in namespace "z1" at level 2 on interface "i1" should be up
    And ping from "z1" to "2001:db8:0:ffff::2" should succeed
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean

  @bfd_echo
  Scenario: BFD with Echo in one direction (z1 transmit, z2 receive)
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-echo-tx.yaml" to namespace "z1"
    And I apply config "z2-echo-rx.yaml" to namespace "z2"
    And I wait 10 seconds
    Then isis neighbor in namespace "z1" at level 2 on interface "i1" should be up
    And bfd session in namespace "z1" on interface "i1" should be up
    And bfd session in namespace "z1" on interface "i1" should have echo transmit
    And bfd session in namespace "z2" on interface "i1" should have echo receive
    And ping from "z1" to "2001:db8:0:ffff::2" should succeed
    When I drop bfd control packets in namespace "z2"
    Then bfd session in namespace "z1" on interface "i1" should be down
    And isis neighbor in namespace "z1" at level 2 on interface "i1" should not be up
    When I restore bfd control packets in namespace "z2"
    And I wait 20 seconds
    Then bfd session in namespace "z1" on interface "i1" should be up
    And ping from "z1" to "2001:db8:0:ffff::2" should succeed
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean

  @bfd_echo
  Scenario: BFD with Echo in both directions
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-echo-both.yaml" to namespace "z1"
    And I apply config "z2-echo-both.yaml" to namespace "z2"
    And I wait 10 seconds
    Then isis neighbor in namespace "z1" at level 2 on interface "i1" should be up
    And bfd session in namespace "z1" on interface "i1" should be up
    And bfd session in namespace "z1" on interface "i1" should have echo both
    And bfd session in namespace "z2" on interface "i1" should have echo both
    And ping from "z1" to "2001:db8:0:ffff::2" should succeed
    When I drop bfd control packets in namespace "z2"
    Then bfd session in namespace "z1" on interface "i1" should be down
    And isis neighbor in namespace "z1" at level 2 on interface "i1" should not be up
    When I restore bfd control packets in namespace "z2"
    And I wait 20 seconds
    Then bfd session in namespace "z1" on interface "i1" should be up
    And ping from "z1" to "2001:db8:0:ffff::2" should succeed
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
