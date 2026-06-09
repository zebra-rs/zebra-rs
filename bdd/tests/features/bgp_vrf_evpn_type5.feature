@serial
@bgp_vrf_evpn_type5
Feature: BGP per-VRF EVPN Type-5 (IP Prefix) advertise to a remote PE
  As a network operator
  I want a network configured under `router bgp vrf X afi-safi ipv4`
  with `evpn advertise-ipv4` to be advertised as an EVPN Type-5
  (RFC 9136 IP Prefix) route toward a remote PE
  Using a two-namespace topology where z1 originates the prefix inside
  vrf-blue and z2 peers with z1 over the L2VPN/EVPN address family,
  imports the Type-5 route by matching route-target.

  This is the EVPN-encoded counterpart of the VPNv4 export feature: the
  same per-VRF state (RD, route-target, network) produces a Type-5 NLRI
  instead of a VPNv4 NLRI, exchanged over (AFI=25 / SAFI=70).

  Test Topology:
  ```
  ┌─────────────┐                ┌─────────────┐
  │     z1      │   EVPN iBGP    │     z2      │
  │  AS 65001   │ ◀────────────▶ │  AS 65001   │
  │ vrf-blue:   │                │ vrf-blue:   │
  │  RD 65001:  │                │  RD 65001:  │
  │   100       │                │   200       │
  │  RT 65001:  │                │  RT 65001:  │
  │   100 imp/  │                │   100 imp/  │
  │   exp       │                │   exp       │
  │  net 10.1.  │                │             │
  │   0.0/24    │                │             │
  │  evpn adv-  │                │             │
  │   ipv4      │                │             │
  └─────────────┘                └─────────────┘
   192.168.0.1                    192.168.0.2
  ```

  Config files:
  - z1-1.yaml: AS 65001, vrf-blue with RD 65001:100, RT 65001:100, a
    self-originated network 10.1.0.0/24, and `evpn advertise-ipv4 true`.
    EVPN iBGP to z2.
  - z2-1.yaml: AS 65001, vrf-blue with RD 65001:200, RT 65001:100
    (matching import). EVPN iBGP to z1.

  Scenario: Setup topology
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: z1 advertises the self-originated network as an EVPN Type-5 route
    Given the test topology exists
    Then show command "show bgp evpn" in namespace "z1" should contain "[5]:"
    And show command "show bgp evpn" in namespace "z1" should contain "10.1.0.0"
    And show command "show bgp evpn" in namespace "z1" should contain "65001:100"

  Scenario: z2 receives the EVPN Type-5 route under the originating RD
    Given the test topology exists
    Then show command "show bgp evpn" in namespace "z2" should contain "[5]:"
    And show command "show bgp evpn" in namespace "z2" should contain "10.1.0.0"
    And show command "show bgp evpn" in namespace "z2" should contain "65001:100"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
