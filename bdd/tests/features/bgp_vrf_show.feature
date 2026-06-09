@serial
@bgp_vrf_show
Feature: BGP per-VRF show command
  As a network operator
  I want to inspect the per-VRF state of a running zebra-rs
  Using a single-namespace topology that drives the local config
  callbacks end-to-end so `show ip bgp vrf` reports the committed
  Route Distinguisher / Route Target / MPLS label.

  Test Topology:
  ```
  ┌─────────┐
  │   z1    │   AS 65001
  │ 192.168 │   vrf-blue: RD 65001:100, RT 65001:100
  │  .0.1/24│
  └─────────┘
  ```

  Config files:
  - z1-1.yaml: baseline `router bgp` with no per-VRF block.
  - z1-2.yaml: adds top-level vrf-blue (with RT import/export) and
    a matching `router bgp vrf vrf-blue` block with RD 65001:100.

  Scenario: Setup topology
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I wait 2 seconds for BGP to operate
    Then show command "ip bgp vrf" in namespace "z1" should contain "(no VRFs configured)"

  Scenario: Configure vrf-blue and observe via show
    Given the test topology exists
    When I apply config "z1-2.yaml" to namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then show command "ip bgp vrf" in namespace "z1" should contain "vrf-blue"
    And show command "ip bgp vrf" in namespace "z1" should contain "65001:100"
    And show command "ip bgp vrf vrf-blue" in namespace "z1" should contain "Route Distinguisher: 65001:100"
    And show command "ip bgp vrf vrf-blue" in namespace "z1" should contain "Import RTs"
    And show command "ip bgp vrf vrf-blue" in namespace "z1" should contain "Export RTs"

  Scenario: Inspect vrf-blue via the `show bgp vrf` tree
    # The new `show bgp vrf <name> [ipv4|ipv6] …` tree shares the manager
    # redirect / fall-through plumbing with the legacy `show ip bgp vrf`
    # tree. No per-VRF BGP task runs in this single namespace, so the
    # bare-name form falls through to the per-VRF detail (same output as
    # `show ip bgp vrf vrf-blue`) and the AFI forms report the miss.
    Given the test topology exists
    Then show command "bgp vrf" in namespace "z1" should contain "vrf-blue"
    And show command "bgp vrf vrf-blue" in namespace "z1" should contain "Route Distinguisher: 65001:100"
    And show command "bgp vrf vrf-blue ipv4" in namespace "z1" should contain "is not running"
    And show command "bgp vrf vrf-blue ipv6" in namespace "z1" should contain "is not running"

  Scenario: Remove vrf-blue and observe row drops
    Given the test topology exists
    When I apply config "z1-1.yaml" to namespace "z1"
    And I wait 2 seconds for BGP to operate
    Then show command "ip bgp vrf" in namespace "z1" should contain "(no VRFs configured)"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete bridge "br0"
    Then the test environment should be clean
