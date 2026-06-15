@serial
@bgp_shard_addpath_vpnv6
Feature: BGP VPNv6 AddPath session-up sync at N>1 (all paths sync; per-path withdraw + peer-down)

  AddPath variant of @bgp_shard_sync_vpnv6, and the VPNv6 twin of the
  vpnv4 AddPath test. Two PEs (z1, z2) export the SAME VPNv6 NLRI
  (RD 65001:100, 2001:db8:9::/64) with different AS_PATHs (export-only
  RT, so neither re-imports the other), so the sharded relay z3 holds
  two candidates and AddPath-Sends both to the late peer z4. Pins that
  `route_sync_vpnv6` dumps every candidate and registers each path-id in
  `adj_out`, so a per-path config-withdraw on z1 (driven through the VRF
  self-network withdraw path) and a peer-down (z2) remove only the right
  path-id from a synced AddPath VPNv6 peer.

  Test Topology (z3 is the sharded device under test, 4 shards):
  ```
  z1 (AS65001) PE ┐                            z1 path: "65003 65001"
                  ├─ z3 (AS65003, 4 shards) ── z4 (AS65004) AddPath-recv (late)
  z2 (AS65002) PE ┘  VPNv6 relay, no VRF       z2 path: "65003 65002"
  ```
  z1 and z2 each export RD 65001:100 / 2001:db8:9::/64. All four on bridge br0.

  Scenario: z1, z2 (PEs) and the sharded relay z3 come up; z3 holds two candidates
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8::2/64" on bridge "br0"
    And I create namespace "z3" with IP "2001:db8::3/64" on bridge "br0"
    And I create namespace "z4" with IP "2001:db8::4/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3" with 4 shards
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z3" to "2001:db8::1" should be "Established"
    And BGP session in "z3" to "2001:db8::2" should be "Established"
    And show command "show bgp vpnv6" in namespace "z3" should contain "65001"
    And show command "show bgp vpnv6" in namespace "z3" should contain "65002"

  Scenario: the late AddPath peer z4 gets BOTH paths on sync
    Given the test topology exists
    When I start zebra-rs in namespace "z4"
    And I apply config "z4.yaml" to namespace "z4"
    And I wait 15 seconds for BGP to operate
    Then BGP session in "z3" to "2001:db8::4" should be "Established"
    And show command "show bgp vpnv6" in namespace "z4" should contain "65003 65001"
    And show command "show bgp vpnv6" in namespace "z4" should contain "65003 65002"

  Scenario: z1 withdraws; only z1's path-id is withdrawn from the synced z4
    Given the test topology exists
    When I apply config "z1-withdraw.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp vpnv6" in namespace "z4" should not contain "65003 65001"
    And show command "show bgp vpnv6" in namespace "z4" should contain "65003 65002"

  Scenario: z2's session drops; the surviving path is withdrawn from z4 too
    Given the test topology exists
    Then show command "show bgp vpnv6" in namespace "z4" should contain "65003 65002"
    When I stop zebra-rs in namespace "z2"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z3" to "2001:db8::2" should not be "Established"
    And show command "show bgp vpnv6" in namespace "z4" should not contain "65003 65002"

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
