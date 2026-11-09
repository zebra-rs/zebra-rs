@serial
@bgp_unnumbered_remote_as_external
Feature: BGP unnumbered neighbor with remote-as external
  As a network operator running BGP over IPv6-only point-to-point links
  I want to configure each `interface-neighbor` with `remote-as external`
  So that every fabric link carries the same config and the neighbor's
  AS is learned from its OPEN, as FRR's shorthand does.

  An `external` neighbor holds the placeholder AS 0 until the OPEN, and
  every OPEN is accepted from any AS but ours. Before this was built the
  peer never dialed (AS 0 failed the dial gate) and an inbound OPEN
  failed the AS check, so a link with `external` on both ends never came
  up.

  Test Topology (P2P veth, link-local only — no v4/global-v6 addrs on
  i1; the LAN prefixes live on dummy interfaces):
  ```
   10.10.1.0/24 (lan)                      10.10.2.0/24 (lan)
        (i1)                                   (i1)
    ┌────┴────┐                            ┌────┴────┐
    │   z1    │────────── P2P ─────────────│   z2    │
    │ AS65001 │       fe80:: <-> fe80::    │ AS65002 │
    └─────────┘                            └─────────┘
       remote-as external                   remote-as external
  ```

  Config files:
  - z1-base.yaml / z2-base.yaml: a bare `router bgp` block, so ND learns
    i1 before RA is enabled (see bgp_unnumbered_neighbor).
  - z1-full.yaml / z2-full.yaml: RA on i1, `interface-neighbor i1
    remote-as external`, and the local LAN /24.

  Scenario: Setup topology
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I create dummy interface "lan" with address "10.10.1.1/24" in namespace "z1"
    And I create dummy interface "lan" with address "10.10.2.1/24" in namespace "z2"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2-base.yaml" to namespace "z2"
    And I wait 2 seconds

  Scenario: Both ends with remote-as external establish and learn each other's AS
    Given the test topology exists
    When I apply config "z1-full.yaml" to namespace "z1"
    And I apply config "z2-full.yaml" to namespace "z2"
    Then BGP session in namespace "z1" should eventually be "Established"
    And BGP session in namespace "z2" should eventually be "Established"
    # Each end shows the AS the other's OPEN carried, not the placeholder.
    And show command "show bgp neighbor i1" in namespace "z1" should contain "remote AS 65002, local AS 65001, external link"
    And show command "show bgp neighbor i1" in namespace "z2" should contain "remote AS 65001, local AS 65002, external link"
    And kernel route "10.10.2.0/24" in namespace "z1" should eventually contain "via inet6 fe80::"
    And kernel route "10.10.1.0/24" in namespace "z2" should eventually contain "via inet6 fe80::"
    And ping from "z1" to "10.10.2.1" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
