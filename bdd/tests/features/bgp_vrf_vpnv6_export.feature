@serial
@bgp_vrf_vpnv6_export
Feature: BGP per-VRF VPNv6 origination (network) + receive on a remote PE

  Regression guard for VPNv6 VRF-`network` origination — the v6 sibling of
  `materialize_self_originated_networks` in vrf/spawn.rs that was missing —
  and the VPNv6 advertise path (V6Batch). z1 originates two v6 networks
  inside vrf-blue at VRF spawn; they are exported as VPNv6 NLRIs and
  received by z2. Killing z1 withdraws them from z2.

  Topology: z1 (RD 65001:100) <-VPNv6 iBGP-> z2 (RD 65001:200), both AS
  65001, vrf-blue importing/exporting RT 65001:100, over a native IPv6 link
  (so VPNv6 next-hop-self is a valid v6 address).

  Scenario: Setup topology (z1 originates its vrf-blue v6 networks at spawn)
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8::2/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "2001:db8::2" should be "Established"
    And BGP session in "z2" to "2001:db8::1" should be "Established"

  Scenario: z1 originates the vrf-blue v6 networks; z2 receives them as VPNv6
    Given the test topology exists
    Then show command "show bgp vpnv6" in namespace "z1" should contain "2001:db8:a::/64"
    And show command "show bgp vpnv6" in namespace "z1" should contain "2001:db8:b::/64"
    And show command "show bgp vpnv6" in namespace "z2" should contain "2001:db8:a::/64"
    And show command "show bgp vpnv6" in namespace "z2" should contain "2001:db8:b::/64"
    And show command "show bgp vpnv6" in namespace "z2" should contain "65001:100"

  Scenario: Deleting the VRF withdraws its VPNv6 exports from the remote PE
    Given the test topology exists
    # z1-novrf.yaml is z1.yaml minus `router bgp vrf vrf-blue` — the
    # BGP VRF despawn path must withdraw the exported rows from the
    # local VPNv6 Loc-RIB and the remote PE (finding #3: they used to
    # stay advertised while the freed service label was reused).
    When I apply config "z1-novrf.yaml" to namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then show command "show bgp vpnv6" in namespace "z1" should not contain "2001:db8:a::/64"
    And show command "show bgp vpnv6" in namespace "z2" should not contain "2001:db8:a::/64"
    And show command "show bgp vpnv6" in namespace "z2" should not contain "2001:db8:b::/64"
    # Restore for the following scenarios.
    When I apply config "z1.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp vpnv6" in namespace "z2" should contain "2001:db8:a::/64"

  Scenario: z1 dies; z2 withdraws the VPNv6 routes it learned from it
    Given the test topology exists
    Then show command "show bgp vpnv6" in namespace "z2" should contain "2001:db8:a::/64"
    When I stop zebra-rs in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "2001:db8::1" should not be "Established"
    And show command "show bgp vpnv6" in namespace "z2" should not contain "2001:db8:a::/64"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
