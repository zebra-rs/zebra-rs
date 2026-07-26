@serial
@bgp_evpn_srv6_irb
Feature: L2 and L3 EVPN-over-SRv6 coexist on one PE, sharing a SID pool
  As an operator building an IRB fabric, where the same PE bridges within
  a subnet and routes between them
  I want `advertise-all-vni` + `encapsulation srv6` (L2) and a VRF with
  `encapsulation srv6` + `evpn advertise-ipv4/ipv6` (L3) to run together
  on one box, each carving its own SIDs from the one locator, so that the
  bridged and routed halves of a tenant are not mutually exclusive.

  Every other EVPN-over-SRv6 feature exercises exactly one of the two —
  bgp_evpn_srv6_macip is L2 only, bgp_evpn_srv6_type5 is L3 only. Both
  allocators draw from the same per-instance SID pool against the same
  locator, so coexistence is precisely where an allocator collision or a
  reconcile that evicts the other service's SIDs would hide — and it was
  the one shape untested.

  Control-plane scope for the L2 half (End.DT2U/DT2M forward only through
  the cradle tee, which is out of scope here); the L3 half forwards on the
  kernel End.DT46 datapath and is asserted as an installed VRF route.

  ```
   z1 ══════ IS-IS L2 SRv6 ══════ z2
   LOC1 fcbb:bbbb:1::/48         LOC2 fcbb:bbbb:2::/48
   L2: VNI 10  (End.DT2U + End.DT2M)
   L3: vrf-cust rd 65001:100 / :200, RT 65001:100  (End.DT46)
  ```

  Config files (in `bdd/tests/configs/bgp_evpn_srv6_irb/`):
  - z1.yaml, z2.yaml — both services enabled on each PE, one locator each.

  Scenario: Setup a PE pair running both EVPN services
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1z2" to namespace "z2" interface "z2z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I execute "ip link add br10 type bridge" in namespace "z1"
    And I execute "ip link set vxlan10 master br10" in namespace "z1"
    And I execute "ip link set br10 up" in namespace "z1"
    And I execute "ip link add host0 type dummy" in namespace "z1"
    And I execute "ip link set host0 master br10" in namespace "z1"
    And I execute "ip link set host0 up" in namespace "z1"
    And I execute "ip link add br10 type bridge" in namespace "z2"
    And I execute "ip link set vxlan10 master br10" in namespace "z2"
    And I execute "ip link set br10 up" in namespace "z2"
    And I wait 45 seconds
    Then BGP session in "z1" to "2001:db8::2" should be "Established"
    And BGP session in "z2" to "2001:db8::1" should be "Established"

  Scenario: One locator yields distinct L2 and L3 service SIDs
    Given the test topology exists
    # The VRF's End.DT46 and the VNI's End.DT2M are separate allocations
    # from the same pool; both must be present at once.
    Then show command "show segment-routing srv6 sid" in namespace "z1" should eventually contain "End.DT46"
    And show command "show segment-routing srv6 sid" in namespace "z1" should eventually contain "End.DT2M"

  Scenario: The peer receives both the L2 and the L3 routes with their SIDs
    Given the test topology exists
    When I execute "bridge fdb add aa:bb:cc:dd:ee:01 dev host0 master static" in namespace "z1"
    # L2: the MAC route under the auto-derived VNI RD, with End.DT2U.
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "aa:bb:cc:dd:ee:01"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "(End.DT2U)"
    # L3: the VRF prefixes as Type-5 under the configured RD, with End.DT46.
    And show command "show bgp evpn" in namespace "z2" should eventually contain "65001:100"
    And show command "show bgp evpn" in namespace "z2" should contain "10.1.1.0"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "(End.DT46)"
    # Both SIDs came from z1's one locator.
    And show command "show bgp evpn" in namespace "z2" should contain "Remote SID: fcbb:bbbb:1:"

  Scenario: Both services install, each on its own data path
    Given the test topology exists
    # L3 lands in the VRF FIB as SRv6 encapsulation (kernel End.DT46) ...
    Then show command "show ip route vrf vrf-cust" in namespace "z2" should eventually contain "10.1.1.0/24"
    And show command "show ip route vrf vrf-cust" in namespace "z2" should contain "fcbb:bbbb:1:"
    # ... while L2 lands in the EVPN MAC table against the End.DT2U SID.
    And show command "show l2 mac table" in namespace "z2" should eventually contain "aa:bb:cc:dd:ee:01"
    And show command "show l2 mac table" in namespace "z2" should contain "srv6"

  Scenario: Withdrawing the L2 MAC leaves the L3 service untouched
    Given the test topology exists
    When I execute "bridge fdb del aa:bb:cc:dd:ee:01 dev host0 master" in namespace "z1"
    Then show command "show l2 mac table" in namespace "z2" should eventually not contain "aa:bb:cc:dd:ee:01"
    # The shared pool must not have released the VRF's End.DT46 with it.
    And show command "show ip route vrf vrf-cust" in namespace "z2" should contain "10.1.1.0/24"
    And show command "show bgp evpn" in namespace "z2" should contain "(End.DT46)"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
