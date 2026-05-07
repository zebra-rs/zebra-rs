@serial
@bgp_update_group_ipv4
Feature: BGP Update-Group IPv4 Unicast Formation
  As a network operator I want IOS-XR-style update-groups to form
  correctly: peers whose outbound advertisement signature is identical
  cluster into one group, and peers whose signature differs land in
  separate groups. The runtime then shares attribute transform /
  outbound policy work across same-group members (Phase 2) and shares
  encoded UPDATE bytes across non-source members (Phase 3).

  This feature exercises grouping by **outbound policy name**, the
  primary signature differentiator under operator control. Three
  eBGP peers from z1: two share `out-shared`, one uses `out-different`.
  Expected: `show bgp update-group` reports exactly 2 groups on z1.

  Test Topology:
  ```
  ┌──────────────────────────────────────────────────────────────┐
  │                          br0                                 │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
         │               │               │               │
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   z1    │     │   z2    │     │   z3    │     │   z4    │
    │ AS65001 │     │ AS65002 │     │ AS65003 │     │ AS65004 │
    │.0.1/24  │     │.0.2/24  │     │.0.3/24  │     │.0.4/24  │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
  ```

  Config files:
  - z1-1.yaml: AS 65001, three eBGP peers; .2 and .3 attach
    `out-shared`, .4 attaches `out-different`.
  - z2-1.yaml / z3-1.yaml / z4-1.yaml: simple peer back to .0.1.

  Scenario: Setup 3-peer topology and establish all sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.0.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I apply config "z3-1.yaml" to namespace "z3"
    And I apply config "z4-1.yaml" to namespace "z4"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z1" to "192.168.0.3" should be "Established"
    And BGP session in "z1" to "192.168.0.4" should be "Established"

  Scenario: Two peers sharing policy form one update-group; the third forms its own
    Given the test topology exists
    When I wait 1 seconds for BGP to operate
    Then show command "show bgp update-group" in namespace "z1" should contain "2 groups"
    And show command "show bgp update-group" in namespace "z1" should contain "ipv4-unicast.0"
    And show command "show bgp update-group" in namespace "z1" should contain "ipv4-unicast.1"
    And show command "show bgp update-group" in namespace "z1" should contain "out-shared"
    And show command "show bgp update-group" in namespace "z1" should contain "out-different"

  Scenario: Group detail surfaces the negotiated capabilities
    Given the test topology exists
    Then show command "show bgp update-group ipv4-unicast.0" in namespace "z1" should contain "Negotiated capabilities"
    And show command "show bgp update-group ipv4-unicast.0" in namespace "z1" should contain "Signature version"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "z4"
    And I delete bridge "br0"
    Then the test environment should be clean
