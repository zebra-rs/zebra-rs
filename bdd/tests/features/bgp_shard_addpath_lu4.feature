@serial
@bgp_shard_addpath_lu4
Feature: BGP labeled-unicast (v4) AddPath session-up sync at N>1 (all paths sync; per-path withdraw + peer-down)

  AddPath variant of @bgp_shard_sync_lu. Two origins (z1, z2) advertise the
  same LU-v4 prefix, so the sharded z3 holds two candidates and AddPath-Sends
  both to the late peer z4. Pins that `route_sync_labelv4` dumps every
  candidate from `bgp.shard.v4lu.0` and registers each path-id in
  `adj_out.v4lu`, so a per-path withdraw + peer-down remove only the right
  path-id from a synced AddPath LU peer. `show ip bgp labeled-unicast`
  carries the AS_PATH column.

  Test Topology (z3 is the sharded device under test, 4 shards):
  ```
  z1 (AS65001) ┐                        z1 path: "65003 65001"
               ├─ z3 (AS65003, 4 shards) ── z4 (AS65004) AddPath-recv (late)
  z2 (AS65002) ┘  AddPath-send to z4      z2 path: "65003 65002"
  ```
  z1 and z2 each originate LU 10.10.10.0/24. All four on bridge br0.

  Scenario: z1, z2 and the sharded z3 come up; z3 holds two candidates
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.0.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3" with 4 shards
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z3" to "192.168.0.1" should be "Established"
    And BGP session in "z3" to "192.168.0.2" should be "Established"

  Scenario: the late AddPath peer z4 gets BOTH paths on sync
    Given the test topology exists
    When I start zebra-rs in namespace "z4"
    And I apply config "z4.yaml" to namespace "z4"
    And I wait 15 seconds for BGP to operate
    Then BGP session in "z3" to "192.168.0.4" should be "Established"
    And show command "show ip bgp labeled-unicast" in namespace "z4" should contain "65003 65001"
    And show command "show ip bgp labeled-unicast" in namespace "z4" should contain "65003 65002"

  Scenario: z1 withdraws; only z1's path-id is withdrawn from the synced z4
    Given the test topology exists
    When I apply config "z1-withdraw.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show ip bgp labeled-unicast" in namespace "z4" should not contain "65003 65001"
    And show command "show ip bgp labeled-unicast" in namespace "z4" should contain "65003 65002"

  Scenario: z2's session drops; the surviving path is withdrawn from z4 too
    Given the test topology exists
    Then show command "show ip bgp labeled-unicast" in namespace "z4" should contain "65003 65002"
    When I stop zebra-rs in namespace "z2"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z3" to "192.168.0.2" should not be "Established"
    And show command "show ip bgp labeled-unicast" in namespace "z4" should not contain "65003 65002"

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
