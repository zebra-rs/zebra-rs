@serial
@bgp_evpn_gateway_reflood
Feature: BGP EVPN BUM segmentation — gateway re-flood primitive (RFC 9572 §6, Phase 6 control plane)
  As a network operator
  I want a segmentation gateway to partition its learned VTEPs by region and
  compute the split-horizon re-flood set per region — the control-plane
  primitive the (eBPF) BUM-replication dataplane consumes — so that BUM
  ingressing from one region is replicated only to VTEPs in the other regions,
  never back into the region it came from.

  This is the control-plane foundation for the Phase 6 eBPF gateway dataplane;
  no packet forwarding happens yet (the replication offload is a follow-up).

  Test Topology — region A (AS 65001) PE z1 and region B (AS 65002) PE z3 each
  own a VXLAN (VNI 10); the gateway z2 borders both and learns one VTEP per
  region.
  ```
  ┌──────────────────────────────────────────────────────────┐
  │                            br0                            │
  └─────────┬─────────────────┬─────────────────┬─────────────┘
            │                 │                 │
       ┌────┴────┐ iBGP  ┌────┴────┐ eBGP  ┌────┴────┐
       │   z1    │───────│   z2    │───────│   z3    │
       │region A │       │ gateway │       │region B │
       │ VNI 10  │       │a:65001  │       │ VNI 10  │
       │  .0.1   │       │b:65002  │       │  .0.3   │
       └─────────┘       └─────────┘       └─────────┘
  ```

  Scenario: Setup topology and establish the EVPN sessions
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
    And BGP session in "z2" to "192.168.0.3" should be "Established"

  Scenario: The gateway computes a split-horizon re-flood set per region
    Given the test topology exists
    # z2 learns region A's VTEP (192.168.0.1) and region B's VTEP (192.168.0.3).
    # BUM from region A re-floods to region B's VTEP only, and vice versa.
    Then show command "show bgp evpn route-type per-region-imet" in namespace "z2" should eventually contain "gateway re-flood [192.168.0.3]"
    And show command "show bgp evpn route-type per-region-imet" in namespace "z2" should eventually contain "gateway re-flood [192.168.0.1]"

  Scenario: The gateway is the elected DF and forwards
    Given the test topology exists
    # A single gateway per boundary is trivially the DF, so it forwards.
    Then show command "show bgp evpn route-type per-region-imet" in namespace "z2" should eventually contain "this node is DF, forwards"

  Scenario: Per-PE IMET is not propagated across the boundary (still segmented)
    Given the test topology exists
    # The gateway holds each region's per-PE IMET at the boundary; z3 never
    # sees region A's VTEP directly.
    Then show command "show bgp evpn" in namespace "z3" should not contain "[3]:[0]:[32]:[192.168.0.1]"

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
