@serial
@bgp_evpn_vpws_mpls
Feature: BGP EVPN VPWS E-Line signalling over MPLS (RFC 8365 §5.1.3)
  As a network operator
  I want a `vpws` service under `encapsulation mpls` to advertise its
  per-EVI Ethernet A-D route (Type-1) with a per-service MPLS label in
  the label field — drawn from the same dynamic block as VRF and EVI
  labels — and NO Encapsulation extended community (its absence is what
  says MPLS, RFC 8365 §5.1.3), next hop = the router-id the transport
  LSP resolves on; and to bind the remote PE's Type-1 as a PE+label
  endpoint. Each direction carries the label its EGRESS end assigned.

  Control-plane only: no cradle dataplane is attached, so `show bgp evpn
  vpws` reaching `up` means the Type-1 exchange, the label-block grant
  and the PE+label bind all worked.

  Test Topology — two iBGP (AS 65001) EVPN speakers on a shared transport
  bridge br0, one E-Line service between them:
  ```
  ┌─────────────────────────────────┐
  │               br0               │
  └───────┬─────────────────┬───────┘
     ┌────┴────┐       ┌────┴────┐
     │   z1    │       │   z2    │   vpws eline1: evi 100
     │ .0.1/24 │       │ .0.2/24 │   z1 svc-id 101 ⇄ z2 svc-id 102
     │  mpls   │       │  mpls   │   per-PE dynamic service labels
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

  Scenario: Each PE originates a per-EVI Type-1 with a label and no Encapsulation EC
    Given the test topology exists
    # z1 sees z2's per-EVI Ethernet A-D: [1]:[zero-ESI]:[eth-tag=102] ...
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "[1]:[00:00:00:00:00:00:00:00:00:00]:[102]"
    # ... carrying the Layer-2 Attributes EC but NO Encapsulation EC —
    # its absence is the MPLS signal (RFC 8365 §5.1.3).
    And show command "show bgp evpn" in namespace "z1" should contain "l2-attr"
    And show command "show bgp evpn" in namespace "z1" should not contain "ET:8"
    # z2 symmetrically sees z1's Type-1 with Ethernet Tag 101.
    And show command "show bgp evpn" in namespace "z2" should eventually contain "[1]:[00:00:00:00:00:00:00:00:00:00]:[101]"

  Scenario: The VPWS service binds the remote PE and label and reaches up
    Given the test topology exists
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "VPWS service: eline1"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "EVI: 100"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "Service ID: local 101, remote 102"
    # Our Type-1 went out with a service label from the dynamic block
    # (the literal value is the allocator's business, not the test's) ...
    And show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Local Label: "
    # ... and the bound remote end is z2's PE address with z2's label.
    And show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Remote PE: 192.168.0.2 (label "
    And show command "show bgp evpn vpws" in namespace "z1" should contain "State: up"
    And show command "show bgp evpn vpws" in namespace "z2" should eventually contain "Remote PE: 192.168.0.1 (label "
    And show command "show bgp evpn vpws" in namespace "z2" should contain "State: up"
    # No SRv6 and no VXLAN anywhere on the service.
    And show command "show bgp evpn vpws" in namespace "z1" should not contain "Local SID"
    And show command "show bgp evpn vpws" in namespace "z1" should not contain "Local VNI"

  Scenario: A fabric can run mixed encapsulations, one per direction
    Given the test topology exists
    # z2 flips to the default `encapsulation vxlan`: its Type-1 now
    # carries VNI 100 (= the EVI) with the VXLAN EC, z1's still carries
    # an MPLS label with no EC. Each PE binds what the OTHER signalled,
    # so the E-Line stays up asymmetrically — the one-PE-at-a-time
    # migration story, MPLS edition.
    When I apply config "z2-vxlan.yaml" to namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Remote VTEP: 192.168.0.2 (VNI 100)"
    And show command "show bgp evpn vpws" in namespace "z1" should not contain "Remote PE:"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "State: up"
    And show command "show bgp evpn vpws" in namespace "z2" should eventually contain "Remote PE: 192.168.0.1 (label "
    And show command "show bgp evpn vpws" in namespace "z2" should contain "Local VNI: 100"
    And show command "show bgp evpn vpws" in namespace "z2" should contain "State: up"
    # Flip z2 back to MPLS: both directions are PE+label again.
    When I apply config "z2-1.yaml" to namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Remote PE: 192.168.0.2 (label "
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
