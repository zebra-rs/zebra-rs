@ospf_v2_v3_cleanup
Feature: Deleting one OSPF version withdraws its routes and labels, not the other's
  OSPFv2 and OSPFv3 both install their routes and MPLS ILM entries in the
  RIB as OSPF, v2 in IPv4 and v3 in IPv6. Deleting `router ospfv3` left
  its routes behind for good: the RIB's cleanup had no rtype for
  "ospfv3". Deleting `router ospf` withdrew every OSPF route and label,
  OSPFv3's IPv6 ones too, and OSPFv3 never re-installed them.

  r1 and r2 run both versions over one dual-stack point-to-point link,
  both with SR-MPLS. r1's loopback 192.168.1.1/32 carries the OSPFv2
  Prefix-SID index 11 (label 16011), its loopback 2001:db8::1/128 the
  OSPFv3 Prefix-SID index 1 (label 16001); r2's own loopbacks carry
  labels 16012 (v2) and 16002 (v3). r2 deletes one version at a time and
  must keep the other's routes and labels.

  Config files:
  - r1.yaml: OSPFv2 and OSPFv3 with SR-MPLS; loopback Prefix-SIDs 16011 (v2), 16001 (v3).
  - r2.yaml: the same; loopback Prefix-SIDs 16012 (v2), 16002 (v3).

  Scenario: Both versions install r1's loopbacks and Prefix-SIDs on r2
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I connect namespace "r1" interface "r1-r2" to namespace "r2" interface "r2-r1"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    Then kernel route "192.168.1.1" in namespace "r2" should eventually contain "proto ospf"
    And kernel route "2001:db8::1" in namespace "r2" should eventually contain "proto ospf"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "16011"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "16001"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "16012"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "16002"
    And command "ip -f mpls route show" in namespace "r2" should eventually contain "16011"
    And command "ip -f mpls route show" in namespace "r2" should eventually contain "16001"

  Scenario: Deleting OSPFv3 withdraws its IPv6 routes and labels only
    Given the test topology exists
    When I apply command "delete router ospfv3" in namespace "r2"
    Then kernel route "2001:db8::1" in namespace "r2" should eventually be gone
    And show command "show mpls ilm" in namespace "r2" should eventually not contain "16001"
    And show command "show mpls ilm" in namespace "r2" should eventually not contain "16002"
    And command "ip -f mpls route show" in namespace "r2" should eventually not contain "16001"
    # The cleanup has run, so OSPFv2's routes and labels must still be there.
    And kernel route "192.168.1.1" in namespace "r2" should eventually contain "proto ospf"
    And show command "show mpls ilm" in namespace "r2" should contain "16011"
    And show command "show mpls ilm" in namespace "r2" should contain "16012"
    And command "ip -f mpls route show" in namespace "r2" should eventually contain "16011"

  Scenario: OSPFv3 comes back
    Given the test topology exists
    When I apply config "r2.yaml" to namespace "r2"
    # The new instance has converged, so nothing of it is still on its
    # way when the next scenario's cleanup runs.
    Then show command "show ospfv3 neighbor" in namespace "r2" should eventually contain "Full"
    And kernel route "2001:db8::1" in namespace "r2" should eventually contain "proto ospf"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "16001"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "16002"
    And command "ip -f mpls route show" in namespace "r2" should eventually contain "16001"

  Scenario: Deleting OSPFv2 withdraws its IPv4 routes and labels only
    Given the test topology exists
    When I apply command "delete router ospf" in namespace "r2"
    Then kernel route "192.168.1.1" in namespace "r2" should eventually be gone
    And show command "show mpls ilm" in namespace "r2" should eventually not contain "16011"
    And show command "show mpls ilm" in namespace "r2" should eventually not contain "16012"
    And command "ip -f mpls route show" in namespace "r2" should eventually not contain "16011"
    # The cleanup has run, so OSPFv3's routes and labels must still be there.
    And kernel route "2001:db8::1" in namespace "r2" should eventually contain "proto ospf"
    And show command "show mpls ilm" in namespace "r2" should contain "16001"
    And show command "show mpls ilm" in namespace "r2" should contain "16002"
    And command "ip -f mpls route show" in namespace "r2" should eventually contain "16001"

  Scenario: Teardown
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
