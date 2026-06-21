@serial
@bgp_evpn_gateway_df
Feature: BGP EVPN BUM segmentation — DF-gated gateway re-flood (RFC 9572 §5.3.1, Phase 6.2)
  As a network operator
  I want only the elected Designated Forwarder among the gateways bordering a
  region to deliver BUM into it, so that with multiple redundant gateways no
  duplicate BUM is produced — the standby gateway drops the region from its
  re-flood set.

  Control-plane only (the eBPF replication is a follow-up). Two gateways z2 and
  z4 border both region A (z1) and region B (z3); z2 (lower address) wins the
  modulus DF election for both regions, so z2 re-floods and z4 stays standby.
  ```
  ┌──────────────────────────────────────────────────────────┐
  │                            br0                            │
  └────┬────────────┬────────────┬────────────┬───────────────┘
    ┌──┴──┐      ┌──┴──┐      ┌──┴──┐      ┌──┴──┐
    │ z1  │ iBGP │ z2  │ eBGP │ z3  │ eBGP │ z4  │
    │regA │──────│ DF  │──────│regB │──────│stby │
    │VNI10│      │ .0.2│      │VNI10│      │ .0.4│
    │ .0.1│      └──┬──┘      │ .0.3│      └──┬──┘
    └─────┘         └─────iBGP(gw-gw)─────────┘
  ```

  Scenario: Setup topology and establish the EVPN sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.0.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I apply config "z3-1.yaml" to namespace "z3"
    And I apply config "z4-1.yaml" to namespace "z4"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.4" should be "Established"
    And BGP session in "z2" to "192.168.0.3" should be "Established"

  Scenario: The DF gateway owns both regions and re-floods across the boundary
    Given the test topology exists
    # z2 (.0.2) wins the DF election, so it re-floods BUM from each region to
    # the other region's VTEP.
    Then show command "show bgp evpn route-type per-region-imet" in namespace "z2" should eventually contain "this node is DF, forwards"
    And show command "show bgp evpn route-type per-region-imet" in namespace "z2" should eventually contain "gateway re-flood [192.168.0.3]"
    And show command "show bgp evpn route-type per-region-imet" in namespace "z2" should eventually contain "gateway re-flood [192.168.0.1]"

  Scenario: The standby gateway re-floods nothing (no duplicate BUM)
    Given the test topology exists
    # z4 (.0.4) loses the DF election for both regions, so it owns neither and
    # drops every region from its re-flood set.
    Then show command "show bgp evpn route-type per-region-imet" in namespace "z4" should eventually contain "(standby)"
    And show command "show bgp evpn route-type per-region-imet" in namespace "z4" should not contain "gateway re-flood"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "z4"
    And I delete bridge "br0"
    Then the test environment should be clean
