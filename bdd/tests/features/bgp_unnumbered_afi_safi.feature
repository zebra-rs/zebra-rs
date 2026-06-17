@serial
@bgp_unnumbered_afi_safi
Feature: BGP neighbor-group afi-safi inheritance on an IPv6 unnumbered iBGP session
  As a network operator
  I want an interface-keyed (IPv6 unnumbered) neighbor to inherit its
  enabled address families from a referenced neighbor-group, so that a
  fleet of unnumbered peers shares one afi-safi definition — and a
  later change to the group (disable IPv4) takes effect at the next
  capability negotiation (`clear bgp`), exactly like the per-neighbor
  `afi-safi <name> enabled` knob.

  Configuration shape under test (flattened `neighbor-group` list —
  no `neighbor-groups` container level):

    router bgp {
      neighbor-group dynamic {
        afi-safi ipv4 { enabled true; }
        afi-safi ipv6 { enabled true; }
      }
      interface-neighbor i1 {
        neighbor-group dynamic;
        remote-as internal;
      }
    }

  Test Topology (point-to-point veth, link-local only — no global addrs,
  both routers in AS 65001, `remote-as internal` = iBGP):
  ```
        (i1)                                   (i1)
    ┌────┴────┐                            ┌────┴────┐
    │   z1    │────────── P2P ─────────────│   z2    │
    │ AS65001 │       fe80:: <-> fe80::    │ AS65001 │
    │ id 1.1. │                            │ id 2.2. │
    │   1.1   │                            │   2.2   │
    └─────────┘                            └─────────┘
  ```

  Config files:
  - z1-base.yaml / z2-base.yaml: bare `router bgp` block (two-step
    bring-up so ND learns i1 before RA is enabled — see the files).
  - z1-full.yaml / z2-full.yaml: RA on, `neighbor-group dynamic` with
    afi-safi ipv4+ipv6 enabled, `interface-neighbor i1` referencing it
    with `remote-as internal`, one originated IPv4 /32 and IPv6 /128.
  - z1-v4off.yaml / z2-v4off.yaml: flip the group's ipv4 opinion to
    `enabled false` (additive apply overwrites just that leaf).

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

  Scenario: Group-inherited IPv4+IPv6 capabilities negotiate and both families exchange routes
    Given the test topology exists
    When I apply config "z1-full.yaml" to namespace "z1"
    And I apply config "z2-full.yaml" to namespace "z2"
    Then BGP session in namespace "z1" should eventually be "Established"
    And BGP session in namespace "z2" should eventually be "Established"
    And I wait 5 seconds
    And show command "show bgp neighbors i1" in namespace "z1" should contain "IPv4 Unicast: advertised and received"
    And show command "show bgp neighbors i1" in namespace "z1" should contain "IPv6 Unicast: advertised and received"
    And show command "show bgp neighbor-group dynamic" in namespace "z1" should contain "ipv4 enabled, ipv6 enabled"
    And BGP route in "z2" has "10.0.1.1/32"
    And BGP route in "z1" has "10.0.1.2/32"
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:1::1/128"
    And show command "show bgp ipv6" in namespace "z1" should contain "2001:db8:1::2/128"

  Scenario: Disabling IPv4 in the group applies on clear — IPv6-only session remains
    Given the test topology exists
    # The group flip alone must NOT bounce the session; `clear` makes
    # the new family set negotiate. Clearing z1 is enough to bounce
    # both ends (z2 sees the TCP close and resets its session state).
    When I apply config "z1-v4off.yaml" to namespace "z1"
    And I apply config "z2-v4off.yaml" to namespace "z2"
    And I wait 2 seconds
    And I run "clear bgp ipv4 neighbor i1" in namespace "z1"
    And I wait 3 seconds
    Then BGP session in namespace "z1" should eventually be "Established"
    And BGP session in namespace "z2" should eventually be "Established"
    And I wait 3 seconds
    # Positive assert first so the not-contains below cannot pass
    # vacuously on an empty/garbled show output.
    And show command "show bgp neighbors i1" in namespace "z1" should contain "IPv6 Unicast: advertised and received"
    And show command "show bgp neighbors i1" in namespace "z1" should not contain "IPv4 Unicast:"
    And show command "show bgp neighbors i1" in namespace "z2" should not contain "IPv4 Unicast:"
    And show command "show bgp neighbor-group dynamic" in namespace "z1" should contain "ipv4 disabled, ipv6 enabled"
    # IPv4 routes from the old session were cleaned on the bounce and
    # must not re-sync on the IPv6-only session; IPv6 routes must.
    And BGP route in "z2" does not have "10.0.1.1/32"
    And BGP route in "z1" does not have "10.0.1.2/32"
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:1::1/128"
    And show command "show bgp ipv6" in namespace "z1" should contain "2001:db8:1::2/128"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
