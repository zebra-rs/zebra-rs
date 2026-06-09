@serial
@bgp_vrf_show
Feature: BGP per-VRF show command
  As a network operator
  I want to inspect the per-VRF state of a running zebra-rs
  Using a single-namespace topology that drives the local config
  callbacks end-to-end so `show ip bgp vrf` reports the committed
  Route Distinguisher / MPLS label / task state, and the named forms
  redirect into the spawned per-VRF task.

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
    Then show command "show ip bgp vrf" in namespace "z1" should contain "(no VRFs configured)"

  Scenario: Configure vrf-blue and observe via show
    # The top-level vrf block spawns a per-VRF BGP task, so the bare
    # `show ip bgp vrf` summary lists the row (name, RD, state) and the
    # named form is redirected into the task, rendering that VRF's IPv4
    # unicast RIB (same layout as `show ip bgp`).
    Given the test topology exists
    When I apply config "z1-2.yaml" to namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then show command "show ip bgp vrf" in namespace "z1" should contain "vrf-blue"
    And show command "show ip bgp vrf" in namespace "z1" should contain "65001:100"
    And show command "show ip bgp vrf" in namespace "z1" should contain "running"
    And show command "show ip bgp vrf vrf-blue" in namespace "z1" should contain "Network"

  Scenario: Inspect vrf-blue via the `show bgp vrf` tree
    # The `show bgp vrf <name> [ipv4|ipv6] …` tree shares the manager
    # redirect plumbing with the legacy `show ip bgp vrf` tree: with the
    # per-VRF task running, the bare-name form renders the VRF's IPv4
    # unicast RIB and the explicit AFI forms select the per-AFI tables.
    Given the test topology exists
    Then show command "show bgp vrf" in namespace "z1" should contain "vrf-blue"
    And show command "show bgp vrf vrf-blue" in namespace "z1" should contain "Network"
    And show command "show bgp vrf vrf-blue ipv4" in namespace "z1" should contain "Network"
    And show command "show bgp vrf vrf-blue ipv6" in namespace "z1" should contain "Network"

  Scenario: Remove the BGP VRF block and observe the RD clear
    # vtyctl apply replaces the subtrees present in the file: z1-1.yaml
    # carries `router bgp` without the vrf block, so the per-VRF RD is
    # deleted — but the top-level vrf (absent from the file) persists,
    # so the row and its running task remain with an empty RD.
    Given the test topology exists
    When I apply config "z1-1.yaml" to namespace "z1"
    And I wait 2 seconds for BGP to operate
    Then show command "show ip bgp vrf" in namespace "z1" should not contain "65001:100"
    And show command "show ip bgp vrf" in namespace "z1" should contain "vrf-blue"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete bridge "br0"
    Then the test environment should be clean
