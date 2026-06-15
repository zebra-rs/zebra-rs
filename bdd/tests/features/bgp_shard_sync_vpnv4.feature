@serial
@bgp_shard_sync_vpnv4
Feature: BGP VPNv4 session-up sync at N>1 (sync + withdraw + peer-down reach a late peer)

  VPNv4 counterpart of @bgp_shard_v4_sync. VPNv4 is sync-ingested to the
  main `bgp.shard` (not pooled), so `bgp.shard.v4vpn` stays populated at
  N>1. This pins that `route_sync_vpnv4` dumps the VPNv4 Loc-RIB to a late
  peer AND registers each route in `adj_out` (it already does), so a later
  withdraw + peer-down reach the synced peer.

  z1 is a PE: a route in vrf-blue (RD 65001:100, RT 65001:100) exported to
  VPNv4. z2 (4 shards) is an eBGP VPNv4 relay (no VRF — holds the VPNv4
  routes and re-advertises, Inter-AS Option-B style). z3 establishes early
  (event-driven control); z4 establishes late (session-up route_sync_vpnv4).

  Test Topology (z2 is the sharded device under test, 4 shards):
  ```
                            ┌── z3 (AS65003)  early peer  → event-driven (control)
  z1 (AS65001) ── z2 (AS65002, 4 shards) ──┤
   PE, vrf-blue    VPNv4 relay (no VRF)    └── z4 (AS65004)  late peer  → sync
  ```
  All four on bridge br0 (192.168.0.x). z1 exports 10.1.0.0/24 + 10.2.0.0/24.

  Scenario: z1 (PE) and the sharded VPNv4 relay z2 come up; z2 holds the routes
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.0.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2" with 4 shards
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-routes.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z2" to "192.168.0.3" should be "Established"
    And show command "show bgp vpnv4" in namespace "z2" should contain "10.1.0.0/24"
    And show command "show bgp vpnv4" in namespace "z2" should contain "10.2.0.0/24"

  Scenario: the late peer z4 gets the VPNv4 routes on sync
    Given the test topology exists
    When I start zebra-rs in namespace "z4"
    And I apply config "z4.yaml" to namespace "z4"
    And I wait 15 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.4" should be "Established"
    And show command "show bgp vpnv4" in namespace "z4" should contain "10.1.0.0/24"
    And show command "show bgp vpnv4" in namespace "z4" should contain "10.2.0.0/24"

  Scenario: z1 withdraws one route; the withdraw reaches the synced peer z4
    Given the test topology exists
    When I apply config "z1-withdraw.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp vpnv4" in namespace "z2" should not contain "10.1.0.0/24"
    And show command "show bgp vpnv4" in namespace "z2" should contain "10.2.0.0/24"
    And show command "show bgp vpnv4" in namespace "z4" should not contain "10.1.0.0/24"
    And show command "show bgp vpnv4" in namespace "z4" should contain "10.2.0.0/24"

  Scenario: z1's session drops; the peer-down sweep clears its routes from z4
    Given the test topology exists
    Then show command "show bgp vpnv4" in namespace "z4" should contain "10.2.0.0/24"
    When I stop zebra-rs in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should not be "Established"
    And show command "show bgp vpnv4" in namespace "z2" should not contain "10.2.0.0/24"
    And show command "show bgp vpnv4" in namespace "z4" should not contain "10.2.0.0/24"

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
