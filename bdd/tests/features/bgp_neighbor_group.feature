@serial
@bgp_neighbor_group
Feature: BGP neighbor-group inheritance end-to-end
  As a network operator
  I want a peer that only references a neighbor-group (no per-peer remote-as)
  to inherit the group's remote-as, establish a session, and react to
  later changes to the group's remote-as.

  This exercises the runtime path landed in PRs #758 (static-peer
  resolver), #760 (reactive sweep on group remote-as Set/Delete), and
  #762 (group-level delete cascade) through the full YAML/YANG/CLI
  stack — not just the in-memory callback wiring covered by the
  unit tests in #764.

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
  ```

  Config files:
  - z1-1.yaml: AS 65001, neighbor-group "RR" with remote-as 65002,
    peer 192.168.0.2 references RR (no per-peer remote-as).
  - z1-2.yaml: same shape, but RR's remote-as is 65099 (wrong) —
    used to verify the reactive sweep tears the session down.
  - z2-1.yaml: plain AS 65002 peer to 192.168.0.1 remote-as 65001.
  - z1-3.yaml / z2-2.yaml: GTSM round — z1 inherits ttl-security
    from the GROUP while z2 enables it per-neighbor. GTSM needs both
    ends at TTL 255, so re-establishment proves the inherited knob
    is live on the wire, not just stored.

  Scenario: Setup topology
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"

  Scenario: Inheritance — peer with only a neighbor-group reference establishes
    Given the test topology exists
    When I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: Reactive sweep — changing the group's remote-as drops the session
    Given the test topology exists
    When I apply config "z1-2.yaml" to namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should not be "Established"

  Scenario: Reactive sweep — restoring the group's remote-as brings it back
    Given the test topology exists
    When I apply config "z1-1.yaml" to namespace "z1"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: Inherited ttl-security — group GTSM interoperates with a per-neighbor GTSM far end
    Given the test topology exists
    # z1's member gets GTSM only through the group opinion; z2 turns
    # it on per-neighbor. Both flips bounce their live session (same
    # ritual as the per-neighbor knob), and GTSM only re-establishes
    # when BOTH ends send TTL 255 — so Established below is proof the
    # group-inherited knob reached z1's socket.
    When I apply config "z1-3.yaml" to namespace "z1"
    And I apply config "z2-2.yaml" to namespace "z2"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And show command "show ip bgp neighbors 192.168.0.2" in namespace "z1" should contain "TTL security (GTSM) enabled"
    And show command "show ip bgp neighbors 192.168.0.2" in namespace "z1" should contain "Neighbor-group: RR"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
