@serial
@bgp_evpn_vpws
Feature: BGP EVPN VPWS E-Line signalling over SRv6 (RFC 8214)
  As a network operator
  I want each PE's `vpws` service to advertise a per-EVI Ethernet A-D route
  (Type-1) whose Ethernet Tag is its local service instance id, carrying an
  End.DX2 L2-Service Prefix-SID (RFC 9252 §6.3) carved from the BGP SRv6
  locator, and to bind the remote PE's Type-1 — matched by Ethernet Tag ==
  remote-service-id within the shared EVI — as the E-Line's remote end, so
  the point-to-point service signals with zero per-peer state.

  Control-plane only: no cradle dataplane is attached, so the `interface`
  leaf is just carried state and `show bgp evpn vpws` reaching `up` means
  the Type-1 exchange and the remote-SID bind both worked.

  Test Topology — two iBGP (AS 65001) EVPN speakers on a shared transport
  bridge br0, one E-Line service between them:
  ```
  ┌─────────────────────────────────┐
  │               br0               │
  └───────┬─────────────────┬───────┘
     ┌────┴────┐       ┌────┴────┐
     │   z1    │       │   z2    │   vpws eline1: evi 100
     │ .0.1/24 │       │ .0.2/24 │   z1 svc-id 101 ⇄ z2 svc-id 102
     │  LOC1   │       │  LOC2   │
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

  Scenario: Each PE originates a per-EVI Type-1 the other imports
    Given the test topology exists
    # z1 sees z2's per-EVI Ethernet A-D: [1]:[zero-ESI]:[eth-tag=102 — z2's
    # local service instance id], distinct from a per-ES A-D (MAX-ET).
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "[1]:[00:00:00:00:00:00:00:00:00:00]:[102]"
    # z2 symmetrically sees z1's Type-1 with Ethernet Tag 101.
    And show command "show bgp evpn" in namespace "z2" should eventually contain "[1]:[00:00:00:00:00:00:00:00:00:00]:[101]"

  Scenario: The VPWS service binds the remote End.DX2 SID and reaches up
    Given the test topology exists
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "VPWS service: eline1"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "EVI: 100"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "Service ID: local 101, remote 102"
    # Our Type-1's End.DX2 SID is carved from LOC1's prefix ...
    And show command "show bgp evpn vpws" in namespace "z1" should contain "Local SID (End.DX2): fcbb:bbbb:1:"
    # ... and the bound remote SID from z2's LOC2.
    And show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Remote SID: fcbb:bbbb:2:"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "State: up"
    And show command "show bgp evpn vpws" in namespace "z2" should eventually contain "State: up"

  Scenario: Re-pointing remote-service-id rebinds from the Loc-RIB without a route churn
    Given the test topology exists
    # Point eline1 at a service instance id nobody advertises: the reconcile
    # drops the stale remote SID (z2's Type-1 no longer matches) and the
    # service falls back to advertised.
    When I apply config "z1-repoint.yaml" to namespace "z1"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "State: advertised"
    And show command "show bgp evpn vpws" in namespace "z1" should not contain "Remote SID:"
    # Point it back: the already-imported Type-1 is re-found by the Loc-RIB
    # rescan alone — z2 re-advertises nothing here.
    When I apply config "z1-1.yaml" to namespace "z1"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "State: up"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "Remote SID: fcbb:bbbb:2:"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
