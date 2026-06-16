@serial
@bgp_shard_sync_vpnv6
Feature: BGP VPNv6 session-up sync at N>1 (sync + withdraw + peer-down reach a late peer)

  VPNv6 counterpart of @bgp_shard_sync_vpnv4. VPNv6 is sync-ingested to
  the main `bgp.shard` (not pooled), so its Loc-RIB stays populated at
  N>1. This pins that `route_sync_vpnv6` dumps the VPNv6 Loc-RIB to a
  late peer AND registers each route in `adj_out` (it already does), so
  a later config-withdraw + peer-down reach the synced peer.

  z1 is a PE: a route in vrf-blue (RD 65001:100, RT 65001:100) exported
  to VPNv6. z2 (4 shards) is an eBGP VPNv6 relay (no VRF — holds the
  VPNv6 routes and re-advertises, Inter-AS Option-B style). z3
  establishes early (event-driven control); z4 establishes late
  (session-up route_sync_vpnv6). All sessions ride IPv6 transport.

  Test Topology (z2 is the sharded device under test, 4 shards):
  ```
                            ┌── z3 (AS65003)  early peer  → event-driven (control)
  z1 (AS65001) ── z2 (AS65002, 4 shards) ──┤
   PE, vrf-blue    VPNv6 relay (no VRF)    └── z4 (AS65004)  late peer  → sync
  ```
  All four on bridge br0 (2001:db8::x). z1 exports 2001:db8:1::/64 + 2001:db8:2::/64.

  Scenario: z1 (PE) and the sharded VPNv6 relay z2 come up; z2 holds the routes
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8::2/64" on bridge "br0"
    And I create namespace "z3" with IP "2001:db8::3/64" on bridge "br0"
    And I create namespace "z4" with IP "2001:db8::4/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2" with 4 shards
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-routes.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "2001:db8::1" should be "Established"
    And BGP session in "z2" to "2001:db8::3" should be "Established"
    And show command "show bgp vpnv6" in namespace "z2" should contain "2001:db8:1::/64"
    And show command "show bgp vpnv6" in namespace "z2" should contain "2001:db8:2::/64"

  Scenario: the late peer z4 gets the VPNv6 routes on sync
    Given the test topology exists
    When I start zebra-rs in namespace "z4"
    And I apply config "z4.yaml" to namespace "z4"
    And I wait 15 seconds for BGP to operate
    Then BGP session in "z2" to "2001:db8::4" should be "Established"
    And show command "show bgp vpnv6" in namespace "z4" should contain "2001:db8:1::/64"
    And show command "show bgp vpnv6" in namespace "z4" should contain "2001:db8:2::/64"

  Scenario: z1 withdraws one route; the withdraw reaches the synced peer z4
    Given the test topology exists
    When I apply config "z1-withdraw.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp vpnv6" in namespace "z2" should not contain "2001:db8:1::/64"
    And show command "show bgp vpnv6" in namespace "z2" should contain "2001:db8:2::/64"
    And show command "show bgp vpnv6" in namespace "z4" should not contain "2001:db8:1::/64"
    And show command "show bgp vpnv6" in namespace "z4" should contain "2001:db8:2::/64"

  Scenario: z1's session drops; the peer-down sweep clears its routes from z4
    Given the test topology exists
    Then show command "show bgp vpnv6" in namespace "z4" should contain "2001:db8:2::/64"
    When I stop zebra-rs in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "2001:db8::1" should not be "Established"
    And show command "show bgp vpnv6" in namespace "z2" should not contain "2001:db8:2::/64"
    And show command "show bgp vpnv6" in namespace "z4" should not contain "2001:db8:2::/64"

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
