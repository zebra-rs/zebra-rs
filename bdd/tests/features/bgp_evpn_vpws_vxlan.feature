@serial
@bgp_evpn_vpws_vxlan
Feature: BGP EVPN VPWS E-Line signalling over VXLAN (RFC 8365 §6)
  As a network operator
  I want a `vpws` service under the default `encapsulation vxlan` to
  advertise its per-EVI Ethernet A-D route (Type-1) with the service VNI in
  the label field, the VXLAN Encapsulation extended community and the VTEP
  as next hop — no SRv6 locator anywhere — and to bind the remote PE's
  Type-1 as a VTEP+VNI endpoint, so an E-Line signals over a plain VXLAN
  fabric. Each direction carries the encapsulation its originator
  signalled, which is what lets a fabric migrate one PE at a time.

  Control-plane only: no cradle dataplane is attached, so the `interface`
  leaf is just carried state and `show bgp evpn vpws` reaching `up` means
  the Type-1 exchange and the remote VTEP+VNI bind both worked.

  Test Topology — two iBGP (AS 65001) EVPN speakers on a shared transport
  bridge br0, one E-Line service between them. z1 pins an explicit
  `vni 10100`; z2 leaves the leaf unset, so its VNI defaults to the EVI:
  ```
  ┌─────────────────────────────────┐
  │               br0               │
  └───────┬─────────────────┬───────┘
     ┌────┴────┐       ┌────┴────┐
     │   z1    │       │   z2    │   vpws eline1: evi 100
     │ .0.1/24 │       │ .0.2/24 │   z1 svc-id 101 ⇄ z2 svc-id 102
     │vni 10100│       │ vni=evi │
     └─────────┘       └─────────┘
  ```

  Scenario: Setup topology and EVPN iBGP with a VPWS service on each PE
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

  Scenario: Each PE originates a per-EVI Type-1 carrying the VXLAN encapsulation
    Given the test topology exists
    # z1 sees z2's per-EVI Ethernet A-D: [1]:[zero-ESI]:[eth-tag=102 — z2's
    # local service instance id] ...
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "[1]:[00:00:00:00:00:00:00:00:00:00]:[102]"
    # ... tagged with the VXLAN Encapsulation extended community (RFC 9012
    # type 0x03 / sub 0x0c, tunnel type 8 — rendered `ET:8`) instead of an
    # SRv6 SID.
    And show command "show bgp evpn" in namespace "z1" should contain "ET:8 l2-attr"
    # z2 symmetrically sees z1's Type-1 with Ethernet Tag 101.
    And show command "show bgp evpn" in namespace "z2" should eventually contain "[1]:[00:00:00:00:00:00:00:00:00:00]:[101]"

  Scenario: The VPWS service binds the remote VTEP and VNI and reaches up
    Given the test topology exists
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "VPWS service: eline1"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "EVI: 100"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "Service ID: local 101, remote 102"
    # Our Type-1 went out with the configured VNI ...
    And show command "show bgp evpn vpws" in namespace "z1" should contain "Local VNI: 10100"
    # ... and the bound remote end is z2's VTEP with z2's VNI — which
    # defaulted to the EVI, and travelled in z2's Type-1 label field.
    And show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Remote VTEP: 192.168.0.2 (VNI 100)"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "State: up"
    # z2 reads z1's explicit VNI 10100 from the received label field — the
    # proof the label round-trips, not just the EC.
    Then show command "show bgp evpn vpws" in namespace "z2" should eventually contain "Remote VTEP: 192.168.0.1 (VNI 10100)"
    And show command "show bgp evpn vpws" in namespace "z2" should contain "Local VNI: 100"
    And show command "show bgp evpn vpws" in namespace "z2" should contain "State: up"
    # No SRv6 anywhere: neither side allocated or bound a service SID.
    And show command "show bgp evpn vpws" in namespace "z1" should not contain "Local SID"
    And show command "show bgp evpn vpws" in namespace "z1" should not contain "Remote SID"

  Scenario: Re-pointing remote-service-id rebinds from the Loc-RIB without a route churn
    Given the test topology exists
    # Point eline1 at a service instance id nobody advertises: the reconcile
    # drops the stale remote endpoint and the service falls back to
    # advertised.
    When I apply config "z1-repoint.yaml" to namespace "z1"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "State: advertised"
    And show command "show bgp evpn vpws" in namespace "z1" should not contain "Remote VTEP:"
    # Point it back: the already-imported Type-1 is re-found by the Loc-RIB
    # rescan alone — z2 re-advertises nothing here.
    When I apply config "z1-1.yaml" to namespace "z1"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "State: up"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "Remote VTEP: 192.168.0.2 (VNI 100)"

  Scenario: Changing the vni leaf re-originates and the remote end follows
    Given the test topology exists
    When I apply config "z1-vni.yaml" to namespace "z1"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Local VNI: 10101"
    # z2's bound endpoint tracks z1's re-originated Type-1 label.
    And show command "show bgp evpn vpws" in namespace "z2" should eventually contain "Remote VTEP: 192.168.0.1 (VNI 10101)"
    And show command "show bgp evpn vpws" in namespace "z2" should contain "State: up"

  Scenario: A fabric can run mixed encapsulations, one per direction
    Given the test topology exists
    # z2 flips to `encapsulation srv6` (gaining a locator): its Type-1 now
    # carries an End.DX2 SID, z1's still carries VNI 10101. Each PE binds
    # what the OTHER signalled, so the E-Line stays up asymmetrically —
    # this is the one-PE-at-a-time migration story.
    When I apply config "z2-srv6.yaml" to namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Remote SID: fcbb:bbbb:2:"
    And show command "show bgp evpn vpws" in namespace "z1" should not contain "Remote VTEP:"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "State: up"
    And show command "show bgp evpn vpws" in namespace "z2" should eventually contain "Remote VTEP: 192.168.0.1 (VNI 10101)"
    And show command "show bgp evpn vpws" in namespace "z2" should contain "Local SID (End.DX2): fcbb:bbbb:2:"
    And show command "show bgp evpn vpws" in namespace "z2" should contain "State: up"
    # Flip z2 back to VXLAN: the SRv6 SID is released and both directions
    # are VTEP+VNI again.
    When I apply config "z2-1.yaml" to namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Remote VTEP: 192.168.0.2 (VNI 100)"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "State: up"
    And show command "show bgp evpn vpws" in namespace "z2" should eventually contain "State: up"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
