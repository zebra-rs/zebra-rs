@ospf_v2_v3_adj_sid
Feature: OSPFv2 and OSPFv3 give their Adjacency-SIDs different labels
  OSPFv2 and OSPFv3 each allocate a dynamic Adjacency-SID label for every
  Full adjacency from the same SRLB, 15000 and up. Each used to allocate
  from its own pool, so a router running both gave its first v2 and its
  first v3 adjacency the same label, 15000. The node has one MPLS label
  table, and the ILM kept one OSPF entry per label: one version's
  Adjacency-SID did not forward. The two now draw from the node's shared
  set of local labels.

  r1 and r2 run both versions over one dual-stack point-to-point link,
  both with SR-MPLS: each router has one v2 and one v3 adjacency, so it
  must hold two Adjacency-SID labels, 15000 and 15001.

  Config files:
  - r1.yaml: OSPFv2 and OSPFv3 with SR-MPLS; loopback Prefix-SIDs 16011 (v2), 16001 (v3).
  - r2.yaml: the same; loopback Prefix-SIDs 16012 (v2), 16002 (v3).

  Scenario: Each router installs one Adjacency-SID label per OSPF version
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I connect namespace "r1" interface "r1-r2" to namespace "r2" interface "r2-r1"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    Then show command "show ospf neighbor" in namespace "r2" should eventually contain "Full"
    And show command "show ospfv3 neighbor" in namespace "r2" should eventually contain "Full"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "15000"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "15001"
    And command "ip -f mpls route show" in namespace "r2" should eventually contain "15000"
    And command "ip -f mpls route show" in namespace "r2" should eventually contain "15001"
    And show command "show mpls ilm" in namespace "r1" should eventually contain "15000"
    And show command "show mpls ilm" in namespace "r1" should eventually contain "15001"
    And command "ip -f mpls route show" in namespace "r1" should eventually contain "15000"
    And command "ip -f mpls route show" in namespace "r1" should eventually contain "15001"

  Scenario: Teardown
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
