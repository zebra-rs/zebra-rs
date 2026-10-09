@isis_ospf_adj_sid
Feature: IS-IS and OSPF give their Adjacency-SIDs different labels
  IS-IS, OSPFv2 and OSPFv3 each allocate a dynamic Adjacency-SID label
  for every adjacency from their SRLB, and all three SRLBs start at 15000
  (IS-IS takes the default block's 15000..15099, OSPF 15000..15999).
  IS-IS used to allocate from a pool of its own, so on a router running
  it beside OSPF its first adjacency got 15000 while an OSPF adjacency
  held it too. The node has one MPLS label table, which forwards a label
  one way only: one protocol's Adjacency-SID went the other's way. All
  three now draw from the node's shared set of local labels.

  r1 and r2 run all three protocols over one dual-stack point-to-point
  link, with SR-MPLS: each router has one adjacency per protocol, so it
  must hold three Adjacency-SID labels, 15000, 15001 and 15002.

  Config files:
  - r1.yaml: IS-IS, OSPFv2 and OSPFv3 with SR-MPLS; loopback Prefix-SIDs 16021, 16011, 16001.
  - r2.yaml: the same; loopback Prefix-SIDs 16022, 16012, 16002.

  Scenario: Each router installs one Adjacency-SID label per protocol
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I connect namespace "r1" interface "r1-r2" to namespace "r2" interface "r2-r1"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    Then show command "show isis neighbor" in namespace "r2" should eventually contain "r1"
    And show command "show ospf neighbor" in namespace "r2" should eventually contain "Full"
    And show command "show ospfv3 neighbor" in namespace "r2" should eventually contain "Full"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "15000"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "15001"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "15002"
    And command "ip -f mpls route show" in namespace "r2" should eventually contain "15002"
    And show command "show mpls ilm" in namespace "r1" should eventually contain "15000"
    And show command "show mpls ilm" in namespace "r1" should eventually contain "15001"
    And show command "show mpls ilm" in namespace "r1" should eventually contain "15002"
    And command "ip -f mpls route show" in namespace "r1" should eventually contain "15002"

  Scenario: Teardown
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
