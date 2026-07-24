@serial
@bgp_adv_interval_zero
Feature: BGP zero adv-interval delivers routes across IPv4 families
  As a network operator
  I want `router bgp timer adv-interval ibgp 0` to disable the MRAI
  debounce without stalling advertisement
  Using a two-namespace iBGP topology that carries IPv4 unicast, VPNv4,
  and EVPN over one session, all with adv-interval 0.

  Regression guard for the adv-interval-0 fast-flush path (a 0-second
  MRAI arms a ~1 ms next-tick debounce timer instead of the old
  1 s-clamped one): each family's routes must still converge at the peer.

  Test Topology:
  ```
  ┌─────────────┐                ┌─────────────┐
  │     z1      │   iBGP AS65001 │     z2      │
  │ 192.168.0.1 │ ◀────────────▶ │ 192.168.0.2 │
  │ vrf-blue    │ ipv4/vpnv4/evpn│ vrf-blue    │
  │  RD 65001:  │  adv-interval  │  RD 65001:  │
  │   100       │    ibgp 0      │   200       │
  │  RT 65001:100 imp/exp        │  RT 65001:100 imp/exp
  └─────────────┘                └─────────────┘
  ```

  Config files:
  - z1-1.yaml: AS 65001, adv-interval ibgp 0, neighbor 192.168.0.2 with
    ipv4/vpnv4/evpn address families. Originates ipv4 unicast 10.0.0.1/32
    and vrf-blue net 10.1.0.0/24 (exported to VPNv4 and, via
    `evpn advertise-ipv4`, as an EVPN Type-5).
  - z2-1.yaml: AS 65001, adv-interval ibgp 0, same address families,
    vrf-blue RD 65001:200 with matching import RT.

  Scenario: Setup topology and establish the multiprotocol session
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Established"
    And BGP session in "z2" to "192.168.0.1" should eventually be "Established"

  Scenario: IPv4 unicast route converges with adv-interval 0
    Given the test topology exists
    Then show command "show bgp ipv4" in namespace "z2" should eventually contain "10.0.0.1/32"

  Scenario: VPNv4 route converges with adv-interval 0
    Given the test topology exists
    Then show command "show bgp vpnv4" in namespace "z2" should eventually contain "10.1.0.0/24"
    And show command "show bgp vpnv4" in namespace "z2" should eventually contain "65001:100"

  Scenario: EVPN Type-5 route converges with adv-interval 0
    Given the test topology exists
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "[5]:"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "10.1.0.0"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
