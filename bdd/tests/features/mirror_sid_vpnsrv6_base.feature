@mirror_sid_vpnsrv6_base
@isis
Feature: VRF L3VPN over SRv6 (End.DT46) dataplane forwarding — v4 + v6
  Foundation for the Mirror SID live-traffic test, and the VPNv4-over-SRv6
  support check: two PEs (z1, z2) run IS-IS L2 SRv6 + iBGP VPNv4/VPNv6,
  each with a dual-stack VRF vrf-cust whose v4 and v6 CE prefixes are
  carried with the per-VRF End.DT46 service SID (one dual-family SID for
  both AFIs). Hosts behind z2 must reach hosts behind z1 over both v4 and
  v6 — z2 H.Encaps CE traffic toward z1's End.DT46 SID, z1 decapsulates
  into the VRF.

  ```
   ceB ── z2 ════ z1 ── ceA   (v4 10.x + v6 2001:db8:x in vrf-cust)
        (vrf)  IS-IS  (vrf)
               SRv6
  ```

  Scenario: Build topology and confirm IS-IS + BGP VPNv4/VPNv6
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I create namespace "ceA"
    And I create namespace "ceB"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I connect namespace "z1" interface "ce1" to namespace "ceA" interface "eth0"
    And I connect namespace "z2" interface "ce2" to namespace "ceB" interface "eth0"
    And I add address "10.1.1.2/24" to interface "eth0" in namespace "ceA"
    And I add address "2001:db8:a::2/64" to interface "eth0" in namespace "ceA"
    And I add address "10.2.2.2/24" to interface "eth0" in namespace "ceB"
    And I add address "2001:db8:b::2/64" to interface "eth0" in namespace "ceB"
    And I add route "0.0.0.0/0" via "10.1.1.1" in namespace "ceA"
    And I add route "::/0" via "2001:db8:a::1" in namespace "ceA"
    And I add route "0.0.0.0/0" via "10.2.2.1" in namespace "ceB"
    And I add route "::/0" via "2001:db8:b::1" in namespace "ceB"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 45 seconds
    Then BGP session in "z1" to "2001:db8::2" should be "Established"
    And BGP session in "z2" to "2001:db8::1" should be "Established"

  Scenario: VPNv4 and VPNv6 routes carry SRv6 End.DT46 SIDs
    Given the test topology exists
    Then show command "show bgp vpnv6" in namespace "z2" should contain "2001:db8:a::/64"
    And show command "show bgp vpnv4" in namespace "z2" should contain "10.1.1.0/24"
    And show command "show bgp vpnv6" in namespace "z1" should contain "2001:db8:b::/64"
    And show command "show bgp vpnv4" in namespace "z1" should contain "10.2.2.0/24"

  Scenario: CE-to-CE traffic forwards over the VPNv4/VPNv6 SRv6 dataplane
    Given the test topology exists
    Then ping from "ceB" to "2001:db8:a::2" should eventually succeed
    And ping from "ceB" to "10.1.1.2" should eventually succeed
    And ping from "ceA" to "2001:db8:b::2" should eventually succeed
    And ping from "ceA" to "10.2.2.2" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "ceA"
    And I delete namespace "ceB"
    Then the test environment should be clean
