@serial
@bgp_vrf_hybrid_reexport_attrs
Feature: A re-exported VRF route carries this PE's forwarding attributes, not the origin's
  As a network operator
  I want an `inter-as-hybrid` VRF that re-exports an imported route to
  advertise it with this PE's own forwarding attributes, so a PE that
  receives the re-export forwards to this PE as the VRF's encapsulation
  says, and not toward the PE the route was first imported from.

  A VRF's export starts from the route's attributes as the VRF holds
  them. For an imported route those include the forwarding attributes of
  the PE that first advertised it: the SRv6 L3 Service SID in its
  Prefix-SID attribute, and the Router's MAC and VXLAN Encapsulation
  extended communities of a symmetric-IRB Type-5. An SRv6 VRF replaced
  the Prefix-SID with its own; an MPLS or VXLAN VRF passed the origin's
  on, and the Type-5 path added this PE's Router's MAC beside the
  origin's.

  Test Topology:
  ```
  ┌─────────────────────────────────────────────────────────┐
  │                          br0                            │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │  EVPN    │   z1    │  VPNv4   │   z2    │
     │ scripted│─iBGP────▶│  (DUT)  │─iBGP────▶│ zebra-rs│
     │ Type-5  │          │vrf-blue │          │vrf-blue │
     │ .32.2/24│          │ hybrid  │          │ .32.3/24│
     └─────────┘          │ .32.1/24│          └─────────┘
                          └─────────┘
  ```

  h1 runs tests/scripts/bgp_evpn_type5_send.py and announces
  10.20.0.0/24 as a Type-5 with RT 65000:100, the SRv6 SID
  fc00:0:2:e000:: (End.DT46), Router's MAC 02:aa:bb:cc:dd:ee and the
  VXLAN Encapsulation extended community. z1's vrf-blue (MPLS,
  `inter-as-hybrid`) imports it and re-exports it to z2 as VPNv4 under
  RD 65000:1, and z2 imports that into its own vrf-blue.

  Scenario: Setup topology and establish sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.32.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.32.3/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.32.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.32.3" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_evpn_type5_send.py --rmac 02:aa:bb:cc:dd:ee --vxlan-encap --srv6-sid fc00:0:2:e000:: 192.168.32.1 65000 192.168.32.2 192.168.32.2 10.20.0.0/24" in namespace "h1"
    Then BGP session in "z1" to "192.168.32.2" should eventually be "Established"

  Scenario: z1 receives the Type-5 with the origin's forwarding attributes
    Given the test topology exists
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "10.20.0.0"
    And show command "show bgp evpn" in namespace "z1" should contain "Remote SID: fc00:0:2:e000:: (End.DT46)"
    And show command "show bgp vrf vrf-blue" in namespace "z1" should eventually contain "10.20.0.0/24"

  # The regression assertions: the re-export is z1's route, so it carries
  # z1's export RT and MPLS label and none of h1's tunnel attributes.
  Scenario: z1 re-exports the route without the origin's Router's MAC and encapsulation
    Given the test topology exists
    Then show command "show bgp vpnv4" in namespace "z1" should eventually contain "Route Distinguisher: 65000:1"
    And show command "show bgp vpnv4" in namespace "z1" should contain "rt:65000:100"
    And show command "show bgp vpnv4" in namespace "z1" should not contain "rmac:02:aa:bb:cc:dd:ee"
    And show command "show bgp vpnv4" in namespace "z1" should not contain "VXLAN"

  # Before the fix the re-export carried h1's SRv6 SID: z2 tracked that SID
  # as the route's next hop, could not reach it, and never imported the
  # route; had it reached it, it would have tunnelled straight to h1.
  Scenario: z2 imports the re-export as an MPLS route toward z1
    Given the test topology exists
    Then show command "show bgp vpnv4" in namespace "z2" should eventually contain "Route Distinguisher: 65000:1"
    And show command "show bgp vrf vrf-blue" in namespace "z2" should eventually contain "10.20.0.0/24"
    And show command "show bgp vrf vrf-blue 10.20.0.0/24" in namespace "z2" should not contain "Remote SID"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "h1"
    And I delete bridge "br0"
    Then the test environment should be clean
