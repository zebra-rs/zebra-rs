@isis_bfd_ipv4_lan
@isis
@bfd
Feature: IS-IS BFD over an IPv4 LAN (broadcast) link
  As a network operator running IS-IS over IPv4 broadcast segments
  I want BFD to protect each LAN adjacency
  So that a forwarding failure tears the adjacency down well within the IS-IS
  hold time, and the adjacency stays down (RFC 5882 hold-down) until BFD
  recovers — even while IIHs keep arriving.

  Same intent as the point-to-point feature, but the two routers share a Linux
  bridge (broadcast network type, DIS election). Per-neighbour single-hop BFD
  sessions are built from each end's IPv4 interface address (TLV 132). Each
  scenario is self-contained so the Echo scenarios arm echo-mode before the
  session first comes up.

  BFD-down is induced by dropping inbound UDP/3784 in one namespace: the link
  stays up and IIHs (L2 ISO PDUs, not IP/UDP) keep flowing, so a fast teardown
  is provably BFD's doing — not carrier loss, not the ~30s IS-IS hold timer.

  Test Topology (shared bridge):
  ```
  ┌────────────────────────────────────────┐
  │                  br0                    │
  └────────────┬───────────────┬───────────┘
               │               │
          10.0.1.1/24     10.0.1.2/24
            (vz1ns)            (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          └─────────┘     └─────────┘
       lo 10.255.0.1      lo 10.255.0.2
              /32                  /32
  ```

  Scenario: BFD without Echo protects the LAN adjacency and tears it down on BFD failure
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with loopback and veth interface on the bridge "br0"
    And I create namespace "z2" with loopback and veth interface on the bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-noecho.yaml" to namespace "z1"
    And I apply config "z2-noecho.yaml" to namespace "z2"
    And I wait 15 seconds
    Then isis neighbor in namespace "z1" at level 2 on interface "vz1ns" should be up
    And bfd session in namespace "z1" on interface "vz1ns" should be up
    And bfd session in namespace "z2" on interface "vz2ns" should be up
    And ping from "z1" to "10.255.0.2" should succeed
    # BFD-down isolation: link stays up, IIHs keep flowing.
    When I drop bfd control packets in namespace "z2"
    Then bfd session in namespace "z1" on interface "vz1ns" should be down
    And isis neighbor in namespace "z1" at level 2 on interface "vz1ns" should not be up
    And ping from "z1" to "10.255.0.2" should fail
    # Recovery: BFD re-establishes and IS-IS lifts the hold-down.
    When I restore bfd control packets in namespace "z2"
    And I wait 20 seconds
    Then bfd session in namespace "z1" on interface "vz1ns" should be up
    And isis neighbor in namespace "z1" at level 2 on interface "vz1ns" should be up
    And ping from "z1" to "10.255.0.2" should succeed
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean

  @bfd_echo
  Scenario: BFD with Echo in one direction (z1 transmit, z2 receive)
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with loopback and veth interface on the bridge "br0"
    And I create namespace "z2" with loopback and veth interface on the bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-echo-tx.yaml" to namespace "z1"
    And I apply config "z2-echo-rx.yaml" to namespace "z2"
    And I wait 15 seconds
    Then isis neighbor in namespace "z1" at level 2 on interface "vz1ns" should be up
    And bfd session in namespace "z1" on interface "vz1ns" should be up
    And bfd session in namespace "z1" on interface "vz1ns" should have echo transmit
    And bfd session in namespace "z2" on interface "vz2ns" should have echo receive
    And ping from "z1" to "10.255.0.2" should succeed
    When I drop bfd control packets in namespace "z2"
    Then bfd session in namespace "z1" on interface "vz1ns" should be down
    And isis neighbor in namespace "z1" at level 2 on interface "vz1ns" should not be up
    When I restore bfd control packets in namespace "z2"
    And I wait 20 seconds
    Then bfd session in namespace "z1" on interface "vz1ns" should be up
    And isis neighbor in namespace "z1" at level 2 on interface "vz1ns" should be up
    And ping from "z1" to "10.255.0.2" should succeed
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean

  @bfd_echo
  Scenario: BFD with Echo in both directions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with loopback and veth interface on the bridge "br0"
    And I create namespace "z2" with loopback and veth interface on the bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-echo-both.yaml" to namespace "z1"
    And I apply config "z2-echo-both.yaml" to namespace "z2"
    And I wait 15 seconds
    Then isis neighbor in namespace "z1" at level 2 on interface "vz1ns" should be up
    And bfd session in namespace "z1" on interface "vz1ns" should be up
    And bfd session in namespace "z1" on interface "vz1ns" should have echo both
    And bfd session in namespace "z2" on interface "vz2ns" should have echo both
    And ping from "z1" to "10.255.0.2" should succeed
    When I drop bfd control packets in namespace "z2"
    Then bfd session in namespace "z1" on interface "vz1ns" should be down
    And isis neighbor in namespace "z1" at level 2 on interface "vz1ns" should not be up
    When I restore bfd control packets in namespace "z2"
    And I wait 20 seconds
    Then bfd session in namespace "z1" on interface "vz1ns" should be up
    And isis neighbor in namespace "z1" at level 2 on interface "vz1ns" should be up
    And ping from "z1" to "10.255.0.2" should succeed

  Scenario: Teardown topology
    # Separate scenario so cleanup still runs when a step above fails
    # (a failed step skips the rest of its own scenario only).
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
