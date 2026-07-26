@serial
@bgp_evpn_srv6_macip
Feature: EVPN Type-2 / Type-3 over SRv6 — End.DT2U and End.DT2M signalling
  As a network operator running EVPN bridging over an SRv6 underlay
  I want `afi-safi evpn encapsulation srv6` to carve a per-VNI End.DT2U
  SID onto every Type-2 (MAC/IP) route and an End.DT2M SID onto every
  Type-3 (IMET) route (RFC 9252 SRv6 L2 Service TLVs), and the receiving
  PE to bind the remote End.DT2U as the MAC's overlay destination, so
  that EVPN bridging signals over SRv6 with no VXLAN VTEP anywhere.

  This is the `encapsulation srv6` counterpart of the VXLAN Type-2/Type-3
  path. @bgp_evpn_srv6_p2mp already covers the End.DT2M half via the
  SR-P2MP BUM tree; the unicast End.DT2U half — the `encapsulation srv6`
  leaf itself — had no coverage at all before this feature.

  Control-plane scope: the L2 forwarding plane for End.DT2U / End.DT2M is
  the cradle eBPF tee (the kernel has no seg6local action for either), so
  no `system ebpf` here and no frames are sent. What is proven is the SID
  carve, the advertisement, the receive/import bind, the encapsulation
  toggle, and the withdraw — everything up to the datapath handoff.

  ```
   z1 [br10: vxlan10 + host0]  ══════  z2 [br10: vxlan10]
      LOC1 fcbb:bbbb:1::/48    2001:db8:12::/64   LOC2 fcbb:bbbb:2::/48
      router-id 192.168.0.1                       router-id 192.168.0.2
      VNI 10 -> RD <router-id>:10, RT 65001:10 (auto-derived, RFC 8365)
  ```

  Config files (in `bdd/tests/configs/bgp_evpn_srv6_macip/`):
  - z1.yaml, z2.yaml — `advertise-all-vni` + `encapsulation srv6`, a
    locator each, and the EVPN AFI/SAFI as the only negotiated family.

  Scenario: Setup topology and the EVPN session over SRv6
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1z2" to namespace "z2" interface "z2z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    # Enslave each node's config-created vxlan10 to a learning bridge so a
    # local MAC maps to VNI 10. host0 is a plain dummy port: a MAC parked
    # on it is a local host as far as the bridge FDB is concerned.
    And I execute "ip link add br10 type bridge" in namespace "z1"
    And I execute "ip link set vxlan10 master br10" in namespace "z1"
    And I execute "ip link set br10 up" in namespace "z1"
    And I execute "ip link add host0 type dummy" in namespace "z1"
    And I execute "ip link set host0 master br10" in namespace "z1"
    And I execute "ip link set host0 up" in namespace "z1"
    And I execute "ip link add br10 type bridge" in namespace "z2"
    And I execute "ip link set vxlan10 master br10" in namespace "z2"
    And I execute "ip link set br10 up" in namespace "z2"
    And I wait 12 seconds for BGP to operate
    Then BGP session in "z1" to "2001:db8:12::2" should be "Established"
    And BGP session in "z2" to "2001:db8:12::1" should be "Established"

  Scenario: Each PE's Type-3 IMET carries a per-VNI End.DT2M SID
    Given the test topology exists
    # Our own IMET advertises the SID we will decapsulate BUM on ...
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "Local SID: fcbb:bbbb:1:"
    And show command "show bgp evpn" in namespace "z1" should contain "(End.DT2M)"
    # ... and the peer sees it as the remote end of the flood path.
    And show command "show bgp evpn" in namespace "z2" should eventually contain "Remote SID: fcbb:bbbb:1:"
    And show command "show bgp evpn" in namespace "z2" should contain "(End.DT2M)"

  Scenario: A local MAC originates a Type-2 carrying a per-VNI End.DT2U SID
    Given the test topology exists
    When I execute "bridge fdb add aa:bb:cc:dd:ee:01 dev host0 master static" in namespace "z1"
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "aa:bb:cc:dd:ee:01"
    And show command "show bgp evpn" in namespace "z1" should eventually contain "(End.DT2U)"
    # z2 receives the MAC route with z1's End.DT2U as the unicast target.
    And show command "show bgp evpn" in namespace "z2" should eventually contain "aa:bb:cc:dd:ee:01"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "(End.DT2U)"

  Scenario: The importing PE binds the remote End.DT2U SID to the MAC
    Given the test topology exists
    # The EVPN MAC table is the control-plane view of where a MAC lives.
    # Over SRv6 that is a service SID, not a VXLAN VTEP — the `srv6` encap
    # column distinguishes the two (an IPv6 VTEP would look identical).
    Then show command "show l2 mac table" in namespace "z2" should eventually contain "aa:bb:cc:dd:ee:01"
    And show command "show l2 mac table" in namespace "z2" should contain "srv6"
    And show command "show l2 mac table" in namespace "z2" should contain "fcbb:bbbb:1:"

  Scenario: Toggling the encapsulation re-originates the routes in place
    Given the test topology exists
    # srv6 -> vxlan: the SRv6 L2 Service TLVs must disappear from the
    # re-originated routes without the session bouncing.
    When I apply command "set router bgp afi-safi evpn encapsulation vxlan" in namespace "z1"
    Then show command "show bgp evpn" in namespace "z2" should eventually not contain "(End.DT2U)"
    And BGP session in "z2" to "2001:db8:12::1" should be "Established"
    # vxlan -> srv6: the SIDs come back, from the same locator as before.
    When I apply command "set router bgp afi-safi evpn encapsulation srv6" in namespace "z1"
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "(End.DT2U)"
    And show command "show bgp evpn" in namespace "z2" should contain "Remote SID: fcbb:bbbb:1:"
    And show command "show l2 mac table" in namespace "z2" should eventually contain "srv6"

  Scenario: Withdrawing the local MAC withdraws the Type-2 and its MAC entry
    Given the test topology exists
    When I execute "bridge fdb del aa:bb:cc:dd:ee:01 dev host0 master" in namespace "z1"
    Then show command "show bgp evpn" in namespace "z2" should eventually not contain "aa:bb:cc:dd:ee:01"
    And show command "show l2 mac table" in namespace "z2" should eventually not contain "aa:bb:cc:dd:ee:01"
    # The Type-3 IMET is independent of any MAC and must survive.
    And show command "show bgp evpn" in namespace "z2" should contain "(End.DT2M)"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
