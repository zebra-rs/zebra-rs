@serial
@bgp_update_source_interface
Feature: BGP update-source by interface name
  As a network operator
  I want `update-source <interface>` to source a neighbor's session from
  that interface's address, whatever the address is and whenever it
  comes, so that the configuration names the loopback and never its
  address (SONiC: `neighbor BGPMON update-source Loopback4096`).

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65001 │
           │ 10.0.0. │     │ 10.0.0. │
           │  1/24   │     │  2/24   │
           │ 2001:   │     │ 2001:   │
           │ db8::1  │     │ db8::2  │
           │ lo: set │     │ lo .255 │
           │ by the  │     │  .0.2   │
           │ scenario│     │ :255::2 │
           └─────────┘     └─────────┘
  ```

  z1 dials z2's loopback (iBGP, reached by a static route) with
  `update-source lo`. z2 is the observer: it never dials, and it has a
  passive neighbor for each address z1 could dial from — z1's loopback
  addresses, and z1's link addresses 10.0.0.1 / 2001:db8::1, which are
  what the kernel picks when z1 binds no source. So which of z2's
  sessions comes up says which address z1 sourced the session from:

  - with a loopback address: z1 bound what `lo` gives;
  - with a link address: z1 dialed without the source it was asked for.

  Config files:
  - z2.yaml: the observer.
  - z1-neighbor.yaml: `update-source lo` on the neighbor; `lo` without
    an address.
  - z1-group.yaml: `update-source lo` on a neighbor-group with an IPv4
    and an IPv6 member; `lo` with an address of each family.

  Scenario: A neighbor is not dialed while the interface has no address
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "10.0.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "10.0.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z1-neighbor.yaml" to namespace "z1"
    # Longer than the first idle hold (5 s) by a margin: a z1 that
    # dialed at all would be up with z2's 10.0.0.1 neighbor by now.
    And I wait 15 seconds for BGP to operate
    Then show command "show bgp neighbor" in namespace "z1" should contain "Update source is lo (no usable IPv4 address; neighbor is not dialed)"
    And BGP session in "z1" to "10.255.0.2" should not be "Established"
    And BGP session in "z2" to "10.0.0.1" should not be "Established"

  Scenario: It is dialed from the interface's address when one comes
    Given the test topology exists
    When I apply command "set interface lo ipv4 address 10.255.0.1/32" in namespace "z1"
    Then BGP session in "z2" to "10.255.0.1" should eventually be "Established"
    And BGP session in "z1" to "10.255.0.2" should eventually be "Established"
    And show command "show bgp neighbor" in namespace "z1" should contain "Update source is lo (10.255.0.1)"
    And show command "show bgp ipv4" in namespace "z2" should eventually contain "10.1.1.1/32"
    And BGP session in "z2" to "10.0.0.1" should not be "Established"

  Scenario: The next connect follows the interface to its new address
    Given the test topology exists
    # The loopback is renumbered. The session that is up is left to the
    # address it was opened with; a reset stands in for its hold timer.
    When I apply command "delete interface lo ipv4 address 10.255.0.1/32" in namespace "z1"
    And I apply command "set interface lo ipv4 address 10.255.0.3/32" in namespace "z1"
    Then show command "show bgp neighbor" in namespace "z1" should eventually contain "Update source is lo (10.255.0.3)"
    When I run "clear bgp ipv4 neighbor 10.255.0.2" in namespace "z1"
    Then BGP session in "z2" to "10.255.0.3" should eventually be "Established"
    And BGP session in "z1" to "10.255.0.2" should eventually be "Established"
    And BGP session in "z2" to "10.0.0.1" should not be "Established"

  Scenario: One neighbor-group statement sources IPv4 and IPv6 members
    Given the test topology exists
    When I apply config "z1-group.yaml" to namespace "z1"
    Then BGP session in "z2" to "2001:db8:255::1" should eventually be "Established"
    And BGP session in "z2" to "10.255.0.3" should eventually be "Established"
    And show command "show bgp neighbor-group LOOP" in namespace "z1" should contain "Update-source: lo"
    And show command "show bgp neighbor" in namespace "z1" should eventually contain "Update source is lo (2001:db8:255::1)"
    And show command "show bgp neighbor" in namespace "z1" should eventually contain "Update source is lo (10.255.0.3)"
    And show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:1::/64"
    And BGP session in "z2" to "2001:db8::1" should not be "Established"
    And BGP session in "z2" to "10.0.0.1" should not be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
