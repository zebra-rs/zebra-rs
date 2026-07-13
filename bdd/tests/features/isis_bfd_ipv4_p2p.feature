@isis_bfd_ipv4_p2p
@isis
@bfd
Feature: IS-IS BFD over an IPv4 point-to-point link
  As a network operator running IS-IS over IPv4 links
  I want BFD to protect the point-to-point adjacency
  So that a forwarding failure tears the adjacency down well within the IS-IS
  hold time, and the adjacency stays down (RFC 5882 hold-down) until BFD
  recovers — even while IIHs keep arriving.

  The single-hop BFD session is built from the two ends' IPv4 interface
  addresses (learned via TLV 132). Each scenario is self-contained (own setup
  and teardown). Echo params apply to live sessions too — the last scenario
  toggles echo-mode at runtime and the session must not be re-established.

  BFD-down is induced by dropping inbound UDP/3784 in one namespace: the link
  stays up and IIHs (L2 ISO PDUs, not IP/UDP) keep flowing, so a fast teardown
  is provably BFD's doing — not carrier loss, not the ~30s IS-IS hold timer.

  Test Topology (point-to-point veth):
  ```
     10.0.1.1/24                             10.0.1.2/24
        (i1)                                   (i1)
    ┌────┴────┐                            ┌────┴────┐
    │   z1    │────────── P2P ─────────────│   z2    │
    └─────────┘                            └─────────┘
   lo 10.255.0.1/32                       lo 10.255.0.2/32
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
    And ping from "z1" to "10.255.0.2" should succeed
    # BFD-down isolation: link stays up, IIHs keep flowing.
    When I drop bfd control packets in namespace "z2"
    Then bfd session in namespace "z1" on interface "i1" should be down
    And isis neighbor in namespace "z1" at level 2 on interface "i1" should not be up
    And ping from "z1" to "10.255.0.2" should fail
    # Recovery: BFD re-establishes and IS-IS lifts the hold-down.
    When I restore bfd control packets in namespace "z2"
    And I wait 20 seconds
    Then bfd session in namespace "z1" on interface "i1" should be up
    And isis neighbor in namespace "z1" at level 2 on interface "i1" should be up
    And ping from "z1" to "10.255.0.2" should succeed
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
    And ping from "z1" to "10.255.0.2" should succeed
    When I drop bfd control packets in namespace "z2"
    Then bfd session in namespace "z1" on interface "i1" should be down
    And isis neighbor in namespace "z1" at level 2 on interface "i1" should not be up
    When I restore bfd control packets in namespace "z2"
    And I wait 20 seconds
    Then bfd session in namespace "z1" on interface "i1" should be up
    And isis neighbor in namespace "z1" at level 2 on interface "i1" should be up
    And ping from "z1" to "10.255.0.2" should succeed
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean

  @bfd_echo
  Scenario: Echo transmit is toggled at runtime on the live session
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
    # Runtime delete: the live session must stop originating Echo without
    # being re-established (previously the new params were ignored until the
    # session was torn down and re-created).
    When I apply command "delete router isis interface i1 bfd echo-mode transmit" in namespace "z1"
    Then bfd session in namespace "z1" on interface "i1" should have echo off
    And bfd session in namespace "z1" on interface "i1" should be up
    # Runtime re-enable: Echo resumes on the same live session.
    When I apply command "set router isis interface i1 bfd echo-mode transmit" in namespace "z1"
    Then bfd session in namespace "z1" on interface "i1" should have echo transmit
    And bfd session in namespace "z1" on interface "i1" should be up
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean

  @bfd_echo @bfd_autoattach
  Scenario: BFD Echo auto-attaches eBPF without an explicit interface ebpf line
    # Same as "Echo in both directions" but the configs enable only
    # `system ebpf enabled` — NOT `interface i1 ebpf enabled`. Echo reflection
    # only works when cradle_xdp is attached to i1, so if the session comes up
    # with echo both and survives a BFD-down/restore cycle, the interface was
    # auto-attached purely because a single-hop echo session runs on it.
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-echo-both-autoattach.yaml" to namespace "z1"
    And I apply config "z2-echo-both-autoattach.yaml" to namespace "z2"
    And I wait 10 seconds
    Then isis neighbor in namespace "z1" at level 2 on interface "i1" should be up
    And bfd session in namespace "z1" on interface "i1" should be up
    And bfd session in namespace "z1" on interface "i1" should have echo both
    And bfd session in namespace "z2" on interface "i1" should have echo both
    And ping from "z1" to "10.255.0.2" should succeed
    # The port was attached with no `interface ebpf enabled` leaf: exactly one
    # BFD-sourced port, zero config-sourced.
    And show command "show ebpf" in namespace "z1" should eventually contain "0 config, 1 bfd"
    And show command "show ebpf" in namespace "z2" should eventually contain "0 config, 1 bfd"
    When I drop bfd control packets in namespace "z2"
    Then bfd session in namespace "z1" on interface "i1" should be down
    And isis neighbor in namespace "z1" at level 2 on interface "i1" should not be up
    When I restore bfd control packets in namespace "z2"
    And I wait 20 seconds
    Then bfd session in namespace "z1" on interface "i1" should be up
    And isis neighbor in namespace "z1" at level 2 on interface "i1" should be up
    And ping from "z1" to "10.255.0.2" should succeed
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
    And ping from "z1" to "10.255.0.2" should succeed
    When I drop bfd control packets in namespace "z2"
    Then bfd session in namespace "z1" on interface "i1" should be down
    And isis neighbor in namespace "z1" at level 2 on interface "i1" should not be up
    When I restore bfd control packets in namespace "z2"
    And I wait 20 seconds
    Then bfd session in namespace "z1" on interface "i1" should be up
    And isis neighbor in namespace "z1" at level 2 on interface "i1" should be up
    And ping from "z1" to "10.255.0.2" should succeed
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
