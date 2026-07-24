@serial
@bgp_adv_interval_zero_v6
Feature: BGP zero adv-interval delivers routes across IPv6 families
  As a network operator
  I want `router bgp timer adv-interval ibgp 0` to disable the MRAI
  debounce without stalling advertisement
  Using a two-namespace iBGP topology over IPv6 transport that carries
  IPv6 unicast and VPNv6, both with adv-interval 0.

  IPv6 counterpart of @bgp_adv_interval_zero. Regression guard for the
  adv-interval-0 fast-flush path (a 0-second MRAI arms a ~1 ms next-tick
  debounce timer instead of the old 1 s-clamped one): each family's
  routes must still converge at the peer.

  Test Topology:
  ```
  ┌─────────────┐                ┌─────────────┐
  │     z1      │   iBGP AS65001 │     z2      │
  │ 2001:db8::1 │ ◀────────────▶ │ 2001:db8::2 │
  │ vrf-blue    │   ipv6/vpnv6   │ vrf-blue    │
  │  RD 65001:  │  adv-interval  │  RD 65001:  │
  │   100       │    ibgp 0      │   200       │
  │  RT 65001:100 imp/exp        │  RT 65001:100 imp/exp
  └─────────────┘                └─────────────┘
  ```

  Config files:
  - z1-1.yaml: AS 65001, adv-interval ibgp 0, neighbor 2001:db8::2 with
    ipv6/vpnv6 address families. Originates ipv6 unicast 2001:db8:100::/64
    and vrf-blue net 2001:db8:a::/64 (exported to VPNv6).
  - z2-1.yaml: AS 65001, adv-interval ibgp 0, same address families,
    vrf-blue RD 65001:200 with matching import RT.

  Scenario: Setup topology and establish the multiprotocol session
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8::2/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    Then BGP session in "z1" to "2001:db8::2" should eventually be "Established"
    And BGP session in "z2" to "2001:db8::1" should eventually be "Established"

  Scenario: IPv6 unicast route converges with adv-interval 0
    Given the test topology exists
    Then show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:100::/64"

  Scenario: VPNv6 route converges with adv-interval 0
    Given the test topology exists
    Then show command "show bgp vpnv6" in namespace "z2" should eventually contain "2001:db8:a::/64"
    And show command "show bgp vpnv6" in namespace "z2" should eventually contain "65001:100"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
