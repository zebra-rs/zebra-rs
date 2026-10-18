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

  The RIB views show what was installed: each Adjacency-SID's index in
  the SRLB, the label stack of each nexthop, and no protection role on
  a path with no backup.

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

  Scenario: The ILM shows each Adjacency-SID's index in the SRLB
    Given the test topology exists
    # Each Adjacency-SID label is indexed within the SRLB, from 15000,
    # where it was allocated. Every OSPF one used to read idx 0.
    Then show command "show mpls ilm" in namespace "r2" should eventually contain "SR Adj (idx 0"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "SR Adj (idx 1"
    And show command "show mpls ilm" in namespace "r1" should eventually contain "SR Adj (idx 1"

  Scenario: show nexthop names each label stack
    Given the test topology exists
    # r2 pushes r1's Prefix-SID labels (16011 for v2, 16001 for v3).
    # They used to follow the interface bare: "r2-r1 16011".
    Then show command "show nexthop" in namespace "r2" should eventually contain "via 10.0.12.1, r2-r1, label 16011"
    And show command "show nexthop" in namespace "r2" should eventually contain ", r2-r1, label 16001"

  Scenario: A path with no backup is not tagged Protected
    Given the test topology exists
    # With one link there is no backup, so no path is "Protected".
    Then show command "show ip route detail" in namespace "r2" should eventually contain "10.0.12.1, via r2-r1"
    And show command "show ip route detail" in namespace "r2" should not contain "Protected"
    And show command "show ipv6 route detail" in namespace "r2" should eventually contain ", via r2-r1"
    And show command "show ipv6 route detail" in namespace "r2" should not contain "Protected"

  Scenario: The route legend lists only codes a route can carry
    Given the test topology exists
    Then show command "show ip route" in namespace "r2" should eventually contain "S - static"
    And show command "show ip route" in namespace "r2" should not contain "Stale route"
    # IS-IS keeps its levels apart, so no route is ever inter-area (`ia`).
    And show command "show ip route" in namespace "r2" should contain "L1/L2 - IS-IS level-1/2, B - BGP"

  Scenario: show interface reports that the links accept MPLS
    Given the test topology exists
    # zebra-rs turns MPLS input on for every link it learns
    # (net.mpls.conf.<name>.input); show interface used to report
    # "Label switching is disabled" on all of them.
    Then show command "show interface r2-r1" in namespace "r2" should eventually contain "Label switching is enabled"
    And show command "show interface r2-r1" as JSON in namespace "r2" should eventually contain '"label_switching": "enabled"'

  Scenario: show interface names no parent for a veth
    Given the test topology exists
    # r2-r1 is a veth, not a VLAN: its JSON names no parent. It used to
    # name the local link with its peer's ifindex, often itself.
    Then show command "show interface r2-r1" as JSON in namespace "r2" should eventually contain '"interface": "r2-r1"'
    And show command "show interface r2-r1" as JSON in namespace "r2" should not contain '"parent_index"'

  Scenario: Teardown
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
