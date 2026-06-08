@serial
@bgp_show
Feature: BGP show command tree (show bgp ...)
  As a network operator
  I want the new `show bgp [ipv4|ipv6] [<addr>|<prefix> [longer-prefix]]`
  command tree to render the BGP RIB, including the IPv4 shortcut where
  an address or prefix is typed straight after `show bgp` (no AFI keyword).

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬────────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
  ```

  z1 originates a covering prefix (10.0.0.0/24), a more-specific
  (10.0.0.128/25), and a host route (10.0.0.1/32) so the longest-match
  and longer-prefix views have a real prefix hierarchy to display. z2 is
  the receiver where the `show bgp ...` output is checked.

  Scenario: Setup topology and establish BGP session
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: Routes propagate to z2
    Given the test topology exists
    When I wait 30 seconds for BGP to operate
    Then BGP route in "z2" has "10.0.0.0/24"
    And BGP route in "z2" has "10.0.0.128/25"
    And BGP route in "z2" has "10.0.0.1/32"

  Scenario: "show bgp" defaults to the IPv4 unicast table
    Given the test topology exists
    Then show command "show bgp" in namespace "z2" should contain "10.0.0.0/24"
    And show command "show bgp" in namespace "z2" should contain "10.0.0.128/25"
    And show command "show bgp" in namespace "z2" should contain "10.0.0.1/32"

  Scenario: "show bgp ipv4" renders the same IPv4 unicast table
    Given the test topology exists
    Then show command "show bgp ipv4" in namespace "z2" should contain "10.0.0.0/24"
    And show command "show bgp ipv4" in namespace "z2" should contain "10.0.0.1/32"

  Scenario: "show bgp A.B.C.D" shortcut shows the longest match
    Given the test topology exists
    Then show command "show bgp 10.0.0.1" in namespace "z2" should contain "BGP routing table entry for 10.0.0.1/32"
    And show command "show bgp ipv4 10.0.0.1" in namespace "z2" should contain "BGP routing table entry for 10.0.0.1/32"

  Scenario: "show bgp A.B.C.D/M" shortcut shows the exact prefix
    Given the test topology exists
    Then show command "show bgp 10.0.0.0/24" in namespace "z2" should contain "BGP routing table entry for 10.0.0.0/24"
    And show command "show bgp ipv4 10.0.0.0/24" in namespace "z2" should contain "BGP routing table entry for 10.0.0.0/24"

  Scenario: "longer-prefix" shows the prefix and every more-specific entry
    Given the test topology exists
    Then show command "show bgp 10.0.0.0/24 longer-prefix" in namespace "z2" should contain "10.0.0.0/24"
    And show command "show bgp 10.0.0.0/24 longer-prefix" in namespace "z2" should contain "10.0.0.128/25"
    And show command "show bgp 10.0.0.0/24 longer-prefix" in namespace "z2" should contain "10.0.0.1/32"

  Scenario: "show bgp ipv6" dispatches to the IPv6 unicast table
    Given the test topology exists
    Then show command "show bgp ipv6" in namespace "z2" should contain "Network"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
