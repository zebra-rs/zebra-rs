@serial
@bgp_evpn_srv6_type5
Feature: EVPN Type-5 (IP Prefix) over SRv6 — End.DT46 dataplane forwarding
  As a service provider carrying L3VPN as EVPN rather than VPNv4/VPNv6
  I want a VRF's IPv4 and IPv6 prefixes advertised as EVPN Type-5 routes
  (RFC 9136) carrying the per-VRF End.DT46 service SID (RFC 9252), and the
  receiving PE to install them into the VRF as SRv6 H.Encaps routes, so
  that customer hosts forward end to end with EVPN as the only negotiated
  address family.

  This is the forwarding-level counterpart of @bgp_vrf_evpn_type5, which
  proves the control-plane round trip over MPLS-less defaults. Here the
  encoding change (VPNv4/VPNv6 NLRI -> Type-5 NLRI) is held against the
  SRv6 dataplane that @mirror_sid_vpnsrv6_base proves for VPNv4/VPNv6:
  same VRF, same locators, same End.DT46 SID, same pings — only the NLRI
  encoding differs. The peers negotiate ONLY (AFI=25 / SAFI=70), so a
  passing ping cannot be a VPNv4/VPNv6 path in disguise.

  ```
   ceB ── z2 ════ z1 ── ceA   (v4 10.x + v6 2001:db8:x in vrf-cust)
        (vrf)  IS-IS  (vrf)   z1: LOC1 fcbb:bbbb:1::/48  rd 65001:100
               SRv6           z2: LOC2 fcbb:bbbb:2::/48  rd 65001:200
                              RT 65001:100 import/export on both
  ```

  Config files (in `bdd/tests/configs/bgp_evpn_srv6_type5/`):
  - z1.yaml, z2.yaml — dual-stack vrf-cust, `encapsulation srv6`, and
    `evpn advertise-ipv4` + `advertise-ipv6`; neighbor carries the EVPN
    AFI/SAFI only.

  Scenario: Build the topology and bring up the EVPN session
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

  Scenario: Each PE carves a local End.DT46 service SID from its locator
    Given the test topology exists
    # The per-VRF service SID the Type-5 routes advertise, and the
    # seg6local the far end's traffic decapsulates into.
    Then show command "show segment-routing srv6 sid" in namespace "z1" should eventually contain "End.DT46"
    And show command "show segment-routing srv6 sid" in namespace "z1" should contain "fcbb:bbbb:1:"
    And show command "show segment-routing srv6 sid" in namespace "z2" should eventually contain "End.DT46"
    And show command "show segment-routing srv6 sid" in namespace "z2" should contain "fcbb:bbbb:2:"

  Scenario: Both AFIs are advertised as Type-5 NLRI under the originating RD
    Given the test topology exists
    # z2 sees z1's v4 and v6 customer prefixes as [5]: routes under z1's RD.
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "[5]:"
    And show command "show bgp evpn" in namespace "z2" should contain "65001:100"
    And show command "show bgp evpn" in namespace "z2" should contain "10.1.1.0"
    And show command "show bgp evpn" in namespace "z2" should contain "2001:db8:a::"
    # ... and z1 symmetrically sees z2's, under RD 65001:200.
    And show command "show bgp evpn" in namespace "z1" should eventually contain "65001:200"
    And show command "show bgp evpn" in namespace "z1" should contain "10.2.2.0"
    And show command "show bgp evpn" in namespace "z1" should contain "2001:db8:b::"

  Scenario: The received Type-5 routes carry the originator's End.DT46 SID
    Given the test topology exists
    # The Prefix-SID SRv6 L3 Service TLV (RFC 9252) is what makes these
    # routes forwardable at all — a Type-5 without it has no encapsulation
    # target. z2's view of z1's routes names z1's locator, and vice versa.
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "Remote SID: fcbb:bbbb:1:"
    And show command "show bgp evpn" in namespace "z2" should contain "(End.DT46)"
    And show command "show bgp evpn" in namespace "z1" should eventually contain "Remote SID: fcbb:bbbb:2:"
    # Our own originated Type-5 carries our own SID, labelled Local.
    And show command "show bgp evpn" in namespace "z1" should contain "Local SID: fcbb:bbbb:1:"

  Scenario: Imported Type-5 routes install into the VRF as SRv6 encapsulation
    Given the test topology exists
    # The import reuses the VPNv4/VPNv6 FIB path: an H.Encaps route in the
    # VRF whose segment list is the originator's End.DT46 SID.
    Then show command "show ipv6 route vrf vrf-cust" in namespace "z2" should eventually contain "2001:db8:a::/64"
    And show command "show ipv6 route vrf vrf-cust" in namespace "z2" should contain "fcbb:bbbb:1:"
    And show command "show ip route vrf vrf-cust" in namespace "z2" should eventually contain "10.1.1.0/24"
    And show command "show ip route vrf vrf-cust" in namespace "z2" should contain "fcbb:bbbb:1:"

  Scenario: CE-to-CE traffic forwards over the Type-5 SRv6 dataplane
    Given the test topology exists
    Then ping from "ceB" to "2001:db8:a::2" should eventually succeed
    And ping from "ceB" to "10.1.1.2" should eventually succeed
    And ping from "ceA" to "2001:db8:b::2" should eventually succeed
    And ping from "ceA" to "10.2.2.2" should eventually succeed

  Scenario: Withdrawing a network withdraws the Type-5 route and its FIB entry
    Given the test topology exists
    When I apply command "delete router bgp vrf vrf-cust afi-safi ipv6 network 2001:db8:a::/64" in namespace "z1"
    Then show command "show bgp evpn" in namespace "z2" should eventually not contain "2001:db8:a::"
    And show command "show ipv6 route vrf vrf-cust" in namespace "z2" should eventually not contain "2001:db8:a::/64"
    # The v4 half is untouched — the withdraw is per-prefix, not per-VRF.
    And show command "show ip route vrf vrf-cust" in namespace "z2" should contain "10.1.1.0/24"
    And ping from "ceB" to "10.1.1.2" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "ceA"
    And I delete namespace "ceB"
    Then the test environment should be clean
