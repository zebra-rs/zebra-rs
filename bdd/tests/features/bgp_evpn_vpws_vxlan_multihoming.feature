@serial
@bgp_evpn_vpws_vxlan_multihoming
Feature: BGP EVPN VPWS multihoming over VXLAN — P/B failover binds VTEP and VNI
  As a network operator
  I want a multihomed VPWS pair signalling over VXLAN (RFC 8365 §6) to
  fail over exactly like its SRv6 twin — the election and selection
  machinery is encapsulation-agnostic — with the remote PE re-binding
  BOTH the VTEP and the VNI, because each attached PE advertises its own
  VNI in its own Type-1 label field (downstream-assigned: the two ends
  of one segment need not agree on a number).

  Control-plane only. The topology and carving are bgp_evpn_vpws_multihoming's
  (instance 101 carves to ordinal 101 % 2 = 1 = z2, so the LOWER address
  deliberately is not the DF), under the default `encapsulation vxlan`
  with no SRv6 locator anywhere; z1/z2/z3 advertise VNIs 5111/5222/5333.

  ```
  ┌───────────────────────────────────────────────┐
  │                      br0                      │
  └────┬──────────────────┬──────────────────┬────┘
   ┌───┴───┐          ┌───┴───┐          ┌───┴───┐
   │  z1   │          │  z2   │          │  z3   │  eline1: evi 100
   │ .0.1  │          │ .0.2  │          │ .0.3  │  z1,z2 svc-id 101
   │vni5111│          │vni5222│          │vni5333│  z3    svc-id 103
   └───┬───┘          └───┬───┘          └───────┘
       └─── ES es1 ───────┘   single-active
       00:11:22:33:44:55:66:77:88:99
  ```

  Scenario: Setup topology, two PEs on one Ethernet Segment plus a remote PE
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I apply config "z3-1.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z1" to "192.168.0.3" should be "Established"
    And BGP session in "z2" to "192.168.0.3" should be "Established"

  Scenario: Both attached PEs originate VXLAN Type-1s under the segment's ESI
    Given the test topology exists
    # z3 sees service instance 101 under es1's ESI — carrying the VXLAN
    # Encapsulation EC and each PE's own VNI, not an SRv6 SID.
    Then show command "show bgp evpn" in namespace "z3" should eventually contain "[1]:[00:11:22:33:44:55:66:77:88:99]:[101]"
    And show command "show bgp evpn" in namespace "z3" should contain "ET:8 l2-attr"
    # The carving elected z2 primary, z1 backup (RFC 8214 §5).
    And show command "show bgp evpn vpws" in namespace "z2" should eventually contain "Role: primary (DF 192.168.0.2)"
    And show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: backup (DF 192.168.0.2)"

  Scenario: The remote PE binds the primary's VTEP and VNI
    Given the test topology exists
    # Instance 101 carves to z2: z3 must bind z2's VTEP *with z2's VNI* —
    # not simply the first route it happened to see.
    Then show command "show bgp evpn vpws" in namespace "z3" should eventually contain "Remote VTEP: 192.168.0.2 (VNI 5222)"
    And show command "show bgp evpn vpws" in namespace "z3" should contain "(via 192.168.0.2)"
    And show command "show bgp evpn vpws" in namespace "z3" should contain "Remote endpoints: 2 (multihomed; 1 standing by)"
    And show command "show bgp evpn vpws" in namespace "z3" should contain "State: up"

  Scenario: Losing the primary fails over to the backup's VTEP and VNI
    Given the test topology exists
    # z2 withdraws its per-EVI Type-1: what remains is z1's B=1 route, and
    # the re-selection must swap BOTH halves of the endpoint — the VTEP
    # (192.168.0.2 → .0.1) and the VNI (5222 → 5111), since each PE
    # assigned its own.
    When I apply config "z2-novpws.yaml" to namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z3" should eventually contain "Remote VTEP: 192.168.0.1 (VNI 5111)"
    And show command "show bgp evpn vpws" in namespace "z3" should contain "(via 192.168.0.1, backup)"
    And show command "show bgp evpn vpws" in namespace "z3" should not contain "standing by"
    And show command "show bgp evpn vpws" in namespace "z3" should contain "State: up"
    # Restoring the primary takes the service back — z3 changed nothing.
    When I apply config "z2-1.yaml" to namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z3" should eventually contain "Remote VTEP: 192.168.0.2 (VNI 5222)"
    And show command "show bgp evpn vpws" in namespace "z3" should contain "(via 192.168.0.2)"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
