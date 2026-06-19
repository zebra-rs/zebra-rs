@serial
@bgp_evpn_ar
Feature: BGP EVPN Assisted Replication (RFC 9574) control plane
  As a network operator
  I want zebra-rs to signal RFC 9574 Assisted Replication roles in the
  Type-3 (Inclusive Multicast) IMET route and build the BUM flood list
  accordingly, so that an AR-LEAF offloads BUM replication to an
  AR-REPLICATOR while an RNVE keeps plain ingress replication.

  Test Topology — three iBGP (AS 65001) EVPN speakers on a shared bridge,
  each with a local VXLAN (VNI 10) so every node originates a Type-3 IMET:
  ```
  ┌──────────────────────────────────────────────────────────┐
  │                            br0                            │
  └─────────┬─────────────────┬─────────────────┬─────────────┘
            │                 │                 │
       ┌────┴────┐       ┌────┴────┐       ┌────┴────┐
       │   z1    │       │   z2    │       │   z3    │
       │REPLICATR│       │  LEAF   │       │  RNVE   │
       │ .0.1/24 │       │ .0.2/24 │       │ .0.3/24 │
       │ AR-IP   │       │         │       │         │
       │ .0.101  │       │         │       │         │
       └─────────┘       └─────────┘       └─────────┘
  ```

  Roles (router bgp afi-safi evpn assisted-replication):
  - z1: role replicator, replicator-ip 192.168.0.101 (the AR-IP)
  - z2: role leaf
  - z3: role none (default RNVE)

  The flood list is observed via the kernel VXLAN FDB: the daemon programs
  zero-MAC (00:00:00:00:00:00) rows, one `dst` per flood target. There is
  no actual BUM forwarding here — the FDB *decisions* are the unit under
  test, so the AR-IP need not be a reachable interface.

  Scenario: Setup topology and establish the EVPN iBGP full mesh
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

  Scenario: Type-3 IMET routes are exchanged across the EVPN mesh
    Given the test topology exists
    # Control-plane sanity: every node originates a Type-3 IMET for VNI 10
    # (auto-RT 65001:10) and the others import it. The AR role lives in the
    # PMSI tunnel attribute, which `show bgp evpn` does not render — the
    # AR-specific behavior is asserted via the kernel FDB below.
    Then show command "show bgp evpn" in namespace "z3" should eventually contain "[3]:[0]:[32]:[192.168.0.1]"
    And show command "show bgp evpn" in namespace "z3" should eventually contain "[3]:[0]:[32]:[192.168.0.2]"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "[3]:[0]:[32]:[192.168.0.1]"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "RT:65001:10"

  Scenario: AR-LEAF collapses its BUM flood list to the replicator's AR-IP
    Given the test topology exists
    # z2 (leaf) sends BUM to the single AR-IP, not to each remote VTEP.
    Then bridge fdb "vxlan10" in namespace "z2" should eventually contain "192.168.0.101"
    And bridge fdb "vxlan10" in namespace "z2" should not contain "192.168.0.3"

  Scenario: RNVE floods to every remote VTEP (plain ingress replication)
    Given the test topology exists
    # z3 (RNVE) floods to z1's and z2's IR-IPs, ignoring the AR-IP.
    Then bridge fdb "vxlan10" in namespace "z3" should eventually contain "192.168.0.2"
    And bridge fdb "vxlan10" in namespace "z3" should eventually contain "192.168.0.1"
    And bridge fdb "vxlan10" in namespace "z3" should not contain "192.168.0.101"

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
