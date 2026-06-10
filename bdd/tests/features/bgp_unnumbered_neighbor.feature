@serial
@bgp_unnumbered_neighbor
Feature: BGP IPv6 unnumbered neighbor discovered via Router Advertisements
  As a network operator running BGP over IPv6-only point-to-point links
  I want a peer keyed by its outbound interface (no configured remote
  address) to be discovered from the neighbour's Router Advertisement,
  establish a session over the link-local, and carry IPv4 routes via
  RFC 8950 Extended Next Hop Encoding.

  This exercises the full unnumbered path end-to-end through the
  YAML/YANG/CLI stack — ND RA send + receive, NeighborDiscovered →
  interface-keyed Peer materialization, the active-connect over
  fe80::%ifindex AND the passive accept that binds an inbound
  link-local connection back to its interface-keyed peer (both ends
  connect actively and accept passively, so a collision must resolve
  into a single Established session), and ENHE-carried IPv4 routes.

  Test Topology (point-to-point veth, link-local only — no global addrs):
  ```
        (i1)                                   (i1)
    ┌────┴────┐                            ┌────┴────┐
    │   z1    │────────── P2P ─────────────│   z2    │
    │ AS65001 │       fe80:: <-> fe80::    │ AS65002 │
    │ id 1.1. │                            │ id 2.2. │
    │   1.1   │                            │   2.2   │
    └─────────┘                            └─────────┘
  ```

  Config files:
  - z1-base.yaml / z2-base.yaml: a bare `router bgp` block — spawns ND
    so it learns i1 before RA is enabled (see the files for the race
    this two-step bring-up avoids).
  - z1-full.yaml / z2-full.yaml: enable `send-advertisements` on i1,
    declare `interface-neighbor i1 remote-as N`, and advertise one
    IPv4 /32 (10.0.0.1/32 from z1, 10.0.0.2/32 from z2).

  Note: the interface-keyed peer's remote address is a kernel-assigned
  link-local that the scenario can't name, so the session is asserted
  with the address-agnostic "BGP session in namespace … should
  eventually be …" step (it reads `show ip bgp neighbors`, which lists
  interface-keyed peers).

  Scenario: Setup topology
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2-base.yaml" to namespace "z2"
    And I wait 2 seconds

  Scenario: RA discovery establishes the unnumbered session and exchanges IPv4 routes
    Given the test topology exists
    When I apply config "z1-full.yaml" to namespace "z1"
    And I apply config "z2-full.yaml" to namespace "z2"
    Then BGP session in namespace "z1" should eventually be "Established"
    And BGP session in namespace "z2" should eventually be "Established"
    And I wait 5 seconds
    And BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z1" has "10.0.0.2/32"

  Scenario: The unnumbered peer is listed in summaries and addressable by interface name
    Given the test topology exists
    # The summary identifies an interface-keyed peer by its interface
    # name (the trailing space pins the fixed-width Neighbor column),
    # and `show ip bgp neighbors <ifname>` resolves the peer the
    # dynamic completion offers, rendering the FRR-style
    # `BGP neighbor on <ifname>: <link-local>` identity.
    Then show command "show bgp summary" in namespace "z1" should contain "i1 "
    And show command "show bgp ipv4 summary" in namespace "z1" should contain "i1 "
    And show command "show ip bgp neighbors i1" in namespace "z1" should contain "BGP neighbor on i1: fe80::"

  Scenario: Removing the interface-neighbor tears the session down
    Given the test topology exists
    When I apply config "z1-base.yaml" to namespace "z1"
    Then BGP session in namespace "z1" should eventually not be "Established"
    And BGP session in namespace "z2" should eventually not be "Established"
    And show command "show bgp summary" in namespace "z1" should not contain "i1 "

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
