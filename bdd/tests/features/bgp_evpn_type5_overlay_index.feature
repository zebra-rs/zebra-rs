@serial
@bgp_evpn_type5_overlay_index
Feature: EVPN route reflector keeps a Type-5 route's ESI and Gateway IP
  As a network operator
  I want a zebra-rs route reflector to pass a Type-5 (IP Prefix) route on
  with the ESI and Gateway IP it arrived with, because those two NLRI
  fields are the route's overlay index (RFC 9136 §3.2) — the ESI is what
  IP aliasing resolves through — and a reflector that zeroes them turns
  the route into an interface-less one behind the receivers' backs.

  Before the fix the reflector kept only the label of a received Type-5:
  the ESI and Gateway IP were dropped at receive, `show bgp evpn` did not
  list them, and the reflected route went out with both zeroed. zebra-rs
  originates interface-less Type-5 routes only, so a scripted speaker
  plays the sender.

  Test Topology:
  ```
  ┌─────────────────────────────────────────────────────────┐
  │                          br0                            │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │          │   z1    │          │   z2    │
     │ scripted│          │  (DUT)  │          │ zebra-rs│
     │ Type-5  │─iBGP────▶│  route  │─iBGP────▶│ client  │
     │ AS65000 │          │reflector│          │ AS65000 │
     │ .31.2/24│          │ .31.1/24│          │ .31.3/24│
     └─────────┘          └─────────┘          └─────────┘
  ```

  h1 runs tests/scripts/bgp_evpn_type5_send.py and announces three
  Type-5 routes under RD 192.168.31.2:100:
  - 10.20.0.0/24, ESI 00:11:22:33:44:55:66:77:88:99, Gateway IP 10.20.0.1
  - 2001:db8:20::/64, the same ESI, Gateway IP 2001:db8:20::1
  - 10.30.0.0/24 with neither, the interface-less control

  Scenario: Setup topology and establish sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.31.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.31.3/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.31.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.31.3" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_evpn_type5_send.py 192.168.31.1 65000 192.168.31.2 192.168.31.2 10.20.0.0/24,00:11:22:33:44:55:66:77:88:99,10.20.0.1 2001:db8:20::/64,00:11:22:33:44:55:66:77:88:99,2001:db8:20::1 10.30.0.0/24" in namespace "h1"
    Then BGP session in "z1" to "192.168.31.2" should eventually be "Established"

  Scenario: The reflector lists each Type-5 path's ESI and Gateway IP
    Given the test topology exists
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "10.30.0.0"
    And show command "show bgp evpn" in namespace "z1" should contain "ESI: 00:11:22:33:44:55:66:77:88:99"
    And show command "show bgp evpn" in namespace "z1" should contain "Gateway IP: 10.20.0.1"
    And show command "show bgp evpn" in namespace "z1" should contain "Gateway IP: 2001:db8:20::1"

  # The regression gate: z2 only learns the fields from what z1 sends it.
  Scenario: The reflected Type-5 routes keep their ESI and Gateway IP
    Given the test topology exists
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "10.30.0.0"
    And show command "show bgp evpn" in namespace "z2" should contain "10.20.0.0"
    And show command "show bgp evpn" in namespace "z2" should contain "2001:db8:20::"
    And show command "show bgp evpn" in namespace "z2" should contain "ESI: 00:11:22:33:44:55:66:77:88:99"
    And show command "show bgp evpn" in namespace "z2" should contain "Gateway IP: 10.20.0.1"
    And show command "show bgp evpn" in namespace "z2" should contain "Gateway IP: 2001:db8:20::1"
    And show command "show bgp evpn" as JSON in namespace "z2" should eventually contain '"esi": "00:11:22:33:44:55:66:77:88:99"'
    And show command "show bgp evpn" as JSON in namespace "z2" should eventually contain '"gateway_ip": "2001:db8:20::1"'

  # The interface-less control gains no overlay index on the way.
  Scenario: A Type-5 route without an overlay index is reflected without one
    Given the test topology exists
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "10.30.0.0"
    And show command "show bgp evpn" in namespace "z2" should not contain "Gateway IP: 0.0.0.0"
    And show command "show bgp evpn" in namespace "z2" should not contain "Gateway IP: ::"
    And BGP session in "z1" to "192.168.31.2" should be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "h1"
    And I delete bridge "br0"
    Then the test environment should be clean
