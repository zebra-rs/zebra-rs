@serial
@bgp_vrf_dual_home
Feature: Dual-homed L3VPN prefix survives one PE's withdraw
  As a network operator
  I want a VRF that imports the same prefix from two PEs (two RDs) to
  keep forwarding via the surviving PE when the other withdraws.

  Test Topology:
  ```
  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
  │     z1      │VPNv4 │     z2      │VPNv4 │     z3      │
  │  AS 65001   │◀───▶│  AS 65001   │◀───▶│  AS 65001   │
  │ vrf-blue    │ iBGP │ vrf-blue    │ iBGP │ vrf-blue    │
  │ RD 65001:1  │      │ RD 65001:2  │      │ RD 65001:3  │
  │ net 10.9.   │      │ (import     │      │ net 10.9.   │
  │  0.0/24     │      │  only)      │      │  0.0/24     │
  └─────────────┘      └─────────────┘      └─────────────┘
   192.168.0.1          192.168.0.2          192.168.0.3
  ```

  All three share RT 65001:100. z1 and z3 both export 10.9.0.0/24 under
  their own RDs; z2 imports both into vrf-blue. Review finding #4: the
  two imports used to alias to one Loc-RIB row in z2's VRF, so either
  PE's withdraw removed the row that by then held the OTHER PE's
  still-valid route — a CE-side blackhole.

  Scenario: Setup topology
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I apply config "z3-1.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z2" to "192.168.0.3" should be "Established"

  Scenario: z2 imports the prefix from both RDs
    Given the test topology exists
    Then show command "show bgp vpnv4" in namespace "z2" should eventually contain "Route Distinguisher: 65001:1"
    And show command "show bgp vpnv4" in namespace "z2" should eventually contain "Route Distinguisher: 65001:3"
    And show command "show bgp vrf vrf-blue" in namespace "z2" should eventually contain "10.9.0.0/24"

  Scenario: PE1's withdraw leaves the survivor in the VRF
    Given the test topology exists
    When I apply config "z1-2.yaml" to namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then show command "show bgp vpnv4" in namespace "z2" should eventually not contain "Route Distinguisher: 65001:1"
    And show command "show bgp vpnv4" in namespace "z2" should contain "Route Distinguisher: 65001:3"
    # The regression assertion: the VRF row must survive on PE2's
    # (RD 65001:3) import. Pre-fix, the aliased single row was removed.
    And show command "show bgp vrf vrf-blue" in namespace "z2" should contain "10.9.0.0/24"

  Scenario: The survivor's withdraw empties the VRF row
    Given the test topology exists
    When I apply config "z3-2.yaml" to namespace "z3"
    And I wait 5 seconds for BGP to operate
    Then show command "show bgp vrf vrf-blue" in namespace "z2" should eventually not contain "10.9.0.0/24"

  Scenario: Re-adding the network on PE1 re-imports it
    Given the test topology exists
    When I apply config "z1-1.yaml" to namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then show command "show bgp vrf vrf-blue" in namespace "z2" should eventually contain "10.9.0.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
