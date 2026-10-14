@serial
@bgp_unnumbered_link_local_gap
Feature: An unnumbered neighbor gets the routes it missed while our link-local was gone
  As a network operator running BGP over IPv6-only point-to-point links
  I want a route announced while our link-local on the link is unknown to
  reach the unnumbered neighbor once the link-local is back
  So the neighbor never misses a route over a short address flap.

  IPv4 routes reach an unnumbered neighbor with our IPv6 link-local on
  the link as the next-hop (RFC 8950). While BGP knew no such address the
  update-group flush skipped the neighbor — but the route was already
  recorded as sent, and the address coming back only updated the address
  table: the neighbor never got the route until it changed again. The
  extended next-hop is IPv4-unicast only, so there is no IPv6 twin.

  Test Topology (P2P veth, link-local only on i1):
  ```
    ┌─────────┐                            ┌─────────┐
    │   z1    │────────── P2P ─────────────│   z2    │
    │ AS65001 │  fe80::1 <-> fe80::(auto)  │ AS65002 │
    └─────────┘                            └─────────┘
  ```
  z1's link-local on i1 is pinned to fe80::1 before zebra-rs starts, so the
  feature can delete it and add the same address back while the session
  stays up (a few seconds, well inside the hold time).

  Config files:
  - z1-base.yaml / z2-base.yaml: a bare `router bgp` block (two-step
    bring-up, as in bgp_unnumbered_neighbor).
  - z1-full.yaml / z2-full.yaml: RA on i1, the interface-keyed neighbor, a
    one-second advertisement interval, one IPv4 network each.

  Scenario: Setup; the unnumbered session exchanges IPv4 routes
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I execute "ip -6 addr flush dev i1 scope link" in namespace "z1"
    And I execute "ip -6 addr add fe80::1/64 dev i1" in namespace "z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2-base.yaml" to namespace "z2"
    And I wait 2 seconds
    And I apply config "z1-full.yaml" to namespace "z1"
    And I apply config "z2-full.yaml" to namespace "z2"
    Then BGP session in namespace "z1" should eventually be "Established"
    And BGP session in namespace "z2" should eventually be "Established"
    And show command "show bgp" in namespace "z2" should eventually contain "10.0.0.1/32"

  Scenario: A route announced while z1's link-local is gone reaches z2 once it is back
    Given the test topology exists
    When I execute "ip -6 addr del fe80::1/64 dev i1" in namespace "z1"
    And I wait 2 seconds
    And I apply command "set router bgp afi-safi ipv4 network 10.29.9.0/24" in namespace "z1"
    # The flush runs (one-second interval) while z1 knows no link-local.
    And I wait 3 seconds
    And I execute "ip -6 addr add fe80::1/64 dev i1" in namespace "z1"
    # Pre-fix z2 never got the route: it stayed recorded as sent.
    Then show command "show bgp" in namespace "z2" should eventually contain "10.29.9.0/24"

  Scenario: The session rode out the gap
    Given the test topology exists
    # Control: a route announced now reaches z2 over the same session, so
    # the scenario above did not pass by a session reset's re-sync.
    When I apply command "set router bgp afi-safi ipv4 network 10.29.8.0/24" in namespace "z1"
    Then show command "show bgp" in namespace "z2" should eventually contain "10.29.8.0/24"
    # Neither side has reset the session (the line appears only after one).
    And show command "show bgp neighbor i1" in namespace "z1" should contain "BGP state = Established"
    And show command "show bgp neighbor i1" in namespace "z1" should not contain "Last reset"
    And show command "show bgp neighbor i1" in namespace "z2" should contain "BGP state = Established"
    And show command "show bgp neighbor i1" in namespace "z2" should not contain "Last reset"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
