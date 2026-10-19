@serial
@bgp_vrf_import_no_reexport
Feature: A VRF never re-exports a route it imported
  As a network operator
  I want a PE to stop advertising a VRF prefix into the VPN once it no
  longer has a route of its own for it, even while it still imports
  another PE's route for the same prefix, so that a prefix nobody
  originates any more leaves the VPN.

  Before the fix a VRF exported whatever won best-path after one of its
  own routes went away. When the only route left was another PE's
  import, the VRF re-originated it under its own RD with itself as next
  hop, and an import's withdrawal never took that copy back. Two PEs
  that import each other's routes then kept the prefix alive after both
  stopped originating it: each one's copy re-imported the other's.

  Test Topology:
  ```
  ┌──────────┐ eBGP ┌─────────────┐  VPNv4   ┌─────────────┐
  │    c1    │─────▶│     z1      │◀────────▶│     z2      │
  │ AS 65100 │      │  AS 65001   │   iBGP   │  AS 65001   │
  │ 10.6.0.0 │      │ vrf-blue    │          │ vrf-blue    │
  │  /24     │      │ RD 65001:1  │          │ RD 65001:2  │
  └──────────┘      │ net 10.5.   │          │ net 10.5.   │
   10.9.0.2/30      │  0.0/24     │          │ and 10.6.   │
                    └─────────────┘          └─────────────┘
                     10.9.0.1/30 (c1)         192.168.0.2
                     192.168.0.1
  ```

  Both PEs share RT 65001:100. z1 originates 10.5.0.0/24 with a
  `network` and 10.6.0.0/24 from its CE c1; z2 originates both with
  `network`s. Each PE imports the other's copies, so a PE that drops its
  own route for a prefix still holds the other PE's.

  Scenario: Setup topology
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "c1"
    And I connect namespace "c1" interface "z1" to namespace "z1" interface "c1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "c1"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I apply config "c1-1.yaml" to namespace "c1"
    Then BGP session in "z2" to "192.168.0.1" should eventually be "Established"
    And BGP session in "c1" to "10.9.0.1" should eventually be "Established"

  Scenario: Each PE exports its own routes and imports the other's
    Given the test topology exists
    Then show command "show bgp vpnv4 10.5.0.0/24" in namespace "z2" should eventually contain "Route Distinguisher: 65001:1"
    And show command "show bgp vpnv4 10.6.0.0/24" in namespace "z2" should eventually contain "Route Distinguisher: 65001:1"
    And show command "show bgp vpnv4 10.5.0.0/24" in namespace "z1" should eventually contain "Route Distinguisher: 65001:2"
    And show command "show bgp vpnv4 10.6.0.0/24" in namespace "z1" should eventually contain "Route Distinguisher: 65001:2"

  # The regression assertions: z1 keeps z2's import of the prefix, and
  # before the fix it re-exported it under its own RD 65001:1. One
  # scenario per way z1's own route goes: its CE's withdraw, then its
  # `network`'s removal.
  Scenario: A PE whose CE withdraws a prefix stops exporting it
    Given the test topology exists
    When I apply config "c1-2.yaml" to namespace "c1"
    Then show command "show bgp vpnv4 10.6.0.0/24" in namespace "z2" should eventually not contain "Route Distinguisher: 65001:1"
    And show command "show bgp vrf vrf-blue" in namespace "z1" should contain "10.6.0.0/24"

  Scenario: A PE that drops its network stops exporting the prefix
    Given the test topology exists
    When I apply config "z1-2.yaml" to namespace "z1"
    Then show command "show bgp vpnv4 10.5.0.0/24" in namespace "z2" should eventually not contain "Route Distinguisher: 65001:1"
    And show command "show bgp vrf vrf-blue" in namespace "z1" should contain "10.5.0.0/24"

  # And no prefix outlives every origin: before the fix the two PEs'
  # re-exported copies kept each other alive.
  Scenario: A prefix no PE originates leaves every VRF
    Given the test topology exists
    When I apply config "z2-2.yaml" to namespace "z2"
    Then show command "show bgp vrf vrf-blue" in namespace "z1" should eventually not contain "10.5.0.0/24"
    And show command "show bgp vrf vrf-blue" in namespace "z1" should eventually not contain "10.6.0.0/24"
    And show command "show bgp vrf vrf-blue" in namespace "z2" should eventually not contain "10.5.0.0/24"
    And show command "show bgp vrf vrf-blue" in namespace "z2" should eventually not contain "10.6.0.0/24"

  Scenario: Originating again exports again
    Given the test topology exists
    When I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "c1-1.yaml" to namespace "c1"
    Then show command "show bgp vpnv4 10.5.0.0/24" in namespace "z2" should eventually contain "Route Distinguisher: 65001:1"
    And show command "show bgp vpnv4 10.6.0.0/24" in namespace "z2" should eventually contain "Route Distinguisher: 65001:1"
    And show command "show bgp vrf vrf-blue" in namespace "z2" should eventually contain "10.6.0.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "c1"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "c1"
    And I delete bridge "br0"
    Then the test environment should be clean
