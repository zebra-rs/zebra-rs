@serial
@bgp_rtc_mid_session_v6
Feature: RT Constraint membership that changes mid-session takes effect (IPv6)
  As a network operator
  I want a VRF import route-target added or removed on a PE after its
  session is up to change the VPN routes that PE is sent
  So a new VRF gets its routes without a session reset, and a PE stops
  being sent routes it no longer imports.

  With RT Constraint (RFC 4684) a PE advertises the route-targets it
  imports, and its neighbor sends it only the VPN routes carrying them. A
  zebra-rs PE advertised that membership only at session-up, and a
  neighbor that learned a new membership mid-session only recorded it,
  sending none of the routes it selects; a withdrawn membership was
  ignored. The twin is `bgp_rtc_mid_session`; this one runs over an IPv6
  session, as VPNv6 needs an IPv6 next-hop.

  Test Topology:
  ```
  ┌─────────────────────────────────────┐
  │        br0 2001:db8:68::/64         │
  └───────┬─────────────────────┬───────┘
     ┌────┴────┐           ┌────┴────┐
     │   z1    │── iBGP ───│   z2    │
     │ AS65000 │ vpnv6+rtc │ AS65000 │
     │  ::1    │           │  ::2    │
     └─────────┘           └─────────┘
  ```
  z1 exports 2001:db8:29:1::/64 (VRF red, RT 65000:100) and 2001:db8:29:2::/64 (VRF green,
  RT 65000:200). z2's VRF blue imports 65000:100, so z1 sends z2 only
  2001:db8:29:1::/64. z2 then imports 65000:200 too, and later stops.

  Config files:
  - z1.yaml: the two exporting VRFs; iBGP vpnv6 + RT Constraint to z2.
  - z2.yaml: VRF blue importing 65000:100; iBGP vpnv6 + RT Constraint to z1.

  Scenario: Setup; z2 is sent only the route its membership selects
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8:68::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8:68::2/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "2001:db8:68::2" should eventually be "Established"
    And show command "show bgp vpnv6" in namespace "z2" should eventually contain "2001:db8:29:1::/64"
    And show command "show bgp vpnv6" in namespace "z2" should eventually not contain "2001:db8:29:2::/64"

  Scenario: An import route-target added mid-session brings its routes
    Given the test topology exists
    When I apply command "set vrf blue ipv6 route-target import 65000:200" in namespace "z2"
    # Pre-fix z2 sent no membership update and z1 would not have acted
    # on one: z2 never got the route.
    Then show command "show bgp vpnv6" in namespace "z2" should eventually contain "2001:db8:29:2::/64"
    And BGP session in "z1" to "2001:db8:68::2" should be "Established"

  Scenario: The import route-target removed mid-session withdraws its routes
    Given the test topology exists
    When I apply command "delete vrf blue ipv6 route-target import 65000:200" in namespace "z2"
    Then show command "show bgp vpnv6" in namespace "z2" should eventually not contain "2001:db8:29:2::/64"
    And show command "show bgp vpnv6" in namespace "z2" should contain "2001:db8:29:1::/64"
    And BGP session in "z1" to "2001:db8:68::2" should be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
