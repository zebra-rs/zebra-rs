@serial
@bgp_lu_route_map
Feature: BGP per-peer route-map for IPv4 labeled-unicast (inbound + outbound)
  As a network operator
  I want `neighbor policy in/out <policy>` to filter IPv4 labeled-unicast
  (SAFI 4) routes per neighbor, the same per-peer route-map the IPv4
  unicast path already has. Before this, the labeled-unicast ingest and
  advertise applied no per-neighbor policy, so BGP-LU route-maps were
  silently ignored.

  Policies are configured before the session establishes, so this
  exercises the ingest / advertise / establish-sync policy hooks
  directly.

  Test Topology:
  ```
  ┌─────────────────┐  192.168.0.0/30  ┌─────────────────┐
  │       z1        │                  │       z2        │
  │     AS65001     ├──────────────────┤     AS65002     │
  │ label-v4 origin │   eBGP label-v4  │ label-v4 recv   │
  └─────────────────┘                  └─────────────────┘
  ```

  z1 originates 1.1.1.1/32, 2.2.2.2/32, 3.3.3.3/32 into BGP-LU and binds
  an OUTBOUND policy OUT-LU that denies 3.3.3.3/32. z2 binds an INBOUND
  policy IN-LU that denies 1.1.1.1/32.

  Expected at z2: only 2.2.2.2/32 survives — 1.1.1.1/32 dropped by z2's
  inbound deny, 3.3.3.3/32 never advertised by z1's outbound deny.

  Scenario: Setup and verify inbound + outbound labeled-unicast route-map
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-out.yaml" to namespace "z1"
    And I apply config "z2-in.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp summary" in namespace "z2" should contain "Established"
    # z1 originates all three — the outbound policy gates advertisement,
    # not origination, so 3.3.3.3/32 stays in z1's own LU RIB.
    And show command "show ip bgp labeled-unicast" in namespace "z1" should contain "1.1.1.1/32"
    And show command "show ip bgp labeled-unicast" in namespace "z1" should contain "3.3.3.3/32"
    # The permitted prefix flows end to end.
    And show command "show ip bgp labeled-unicast" in namespace "z2" should contain "2.2.2.2/32"
    # Inbound deny: z1 advertised 1.1.1.1/32 but z2's IN-LU drops it.
    And show command "show ip bgp labeled-unicast" in namespace "z2" should not contain "1.1.1.1/32"
    # Outbound deny: z1's OUT-LU never advertises 3.3.3.3/32 (z2 has no
    # matching inbound deny, so its absence isolates the outbound hook).
    And show command "show ip bgp labeled-unicast" in namespace "z2" should not contain "3.3.3.3/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
