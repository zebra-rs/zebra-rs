@serial
@nd_show
Feature: show ipv6 nd exposes ND counters, neighbors, and BGP discovery state
  As a network operator running BGP unnumbered over IPv6 link-locals
  I want `show ipv6 nd` to report per-interface RA scheduler state,
  sent/received ND packet counters, and the per-source neighbor table,
  and `show bgp neighbor` to report when the interface peer's
  link-local was discovered via ND — so the RA exchange that underpins
  peer discovery is observable instead of a black box.

  This exercises the ND show pipeline end-to-end: the engine's counters
  and neighbor table fill from live RA traffic, the show channel routes
  `show ipv6 nd` to the ND task, and the BGP peer carries the ND
  discovery timestamps stamped at materialization.

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

  Config files mirror the @bgp_unnumbered_neighbor two-step bring-up
  (base then full) so RA-enable cannot lose the race against ND's RIB
  link replay; see z1-base.yaml for the rationale.

  The session reaching Established proves both ends sent AND received
  at least one RA (each side materializes its peer from the other's
  RA), so the counter/neighbor assertions that follow are
  deterministic — no fixed-delay waits are needed beyond the
  session-establishment step itself.

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

  Scenario: ND state is visible once the unnumbered session establishes
    Given the test topology exists
    When I apply config "z1-full.yaml" to namespace "z1"
    And I apply config "z2-full.yaml" to namespace "z2"
    Then BGP session in namespace "z1" should eventually be "Established"
    And BGP session in namespace "z2" should eventually be "Established"
    # Summary lists the interface.
    And show command "show ipv6 nd" in namespace "z1" should contain "i1"
    # Detail: RA send is armed on i1 ...
    And show command "show ipv6 nd interface i1" in namespace "z1" should contain "Interface i1 (ifindex"
    And show command "show ipv6 nd interface i1" in namespace "z1" should contain "Router advertisement: enabled"
    # ... we transmitted at least one RA (z2 learned us from it) ...
    And show command "show ipv6 nd interface i1" in namespace "z1" should not contain "last multicast never"
    # ... and z2's link-local sits in the neighbor table with a
    # recorded last-RA snapshot (proof of a non-zero received-RA count).
    And show command "show ipv6 nd interface i1" in namespace "z1" should contain "fe80::"
    And show command "show ipv6 nd interface i1" in namespace "z1" should contain "last RA: lifetime"

  Scenario: BGP neighbor detail reports the ND discovery
    Given the test topology exists
    Then show command "show bgp neighbor i1" in namespace "z1" should contain "Interface peer: link-local learned via IPv6 ND router advertisement"
    And show command "show bgp neighbor i1" in namespace "z1" should contain "Discovered "

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
