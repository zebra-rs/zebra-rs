@rib_nexthop_per_interface
@ospf
Feature: A gateway address on two interfaces is two nexthops
  The RIB shares one nexthop group between routes with the same gateway.
  It keyed the group on the address alone, so a route whose gateway was
  already in use on another interface joined that group and left by the
  other interface. An address names a neighbor only on its own link:
  link-locals repeat across links, and OSPF hands over each attached route
  as 0.0.0.0 on its interface. The group is now keyed on the interface the
  route's source named as well.

  Test Topology (all links point-to-point, OSPFv2 and OSPFv3):
  ```
               z1 (lo 10.0.0.1, 2001:db8::1)
       z1-z2 /     \ z1-z3
            /       \
   fe80::1 z2       z3 fe80::1      both neighbors use fe80::1 toward z1
            \       /
 2001:db8:24::/64  2001:db8:34::/64
              \   /
               z4
  ```

  Config files:
  - z1.yaml .. z4.yaml: loopbacks, IPv4 link addresses, the two IPv6
    link prefixes behind z2 and z3, OSPFv2 and OSPFv3 (SR-MPLS on the
    loopbacks only).

  Scenario: Build the diamond with fe80::1 on both of z1's neighbors
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I create namespace "z3"
    And I create namespace "z4"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I connect namespace "z1" interface "z1-z3" to namespace "z3" interface "z3-z1"
    And I connect namespace "z2" interface "z2-z4" to namespace "z4" interface "z4-z2"
    And I connect namespace "z3" interface "z3-z4" to namespace "z4" interface "z4-z3"
    # A link-local is unique only on its own link, so z2 and z3 may both
    # be fe80::1 toward z1.
    And I execute "ip link set z2-z1 addrgenmode none" in namespace "z2"
    And I execute "ip -6 addr flush dev z2-z1 scope link" in namespace "z2"
    And I execute "ip -6 addr add fe80::1/64 dev z2-z1" in namespace "z2"
    And I execute "ip link set z3-z1 addrgenmode none" in namespace "z3"
    And I execute "ip -6 addr flush dev z3-z1 scope link" in namespace "z3"
    And I execute "ip -6 addr add fe80::1/64 dev z3-z1" in namespace "z3"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "z4.yaml" to namespace "z4"
    Then show command "show ipv6 route" in namespace "z1" should eventually contain "2001:db8:24::/64 [110/20] via fe80::1"
    And show command "show ipv6 route" in namespace "z1" should eventually contain "2001:db8:34::/64 [110/20] via fe80::1"

  # The two routes below have the same gateway on different links. On
  # main, whichever was installed first decided the interface of both;
  # each check sits in its own scenario so that either one failing shows.
  Scenario: The route through z2 leaves by z1-z2
    Given the test topology exists
    Then kernel route "2001:db8:24::/64" in namespace "z1" should eventually contain "via fe80::1 dev z1-z2"
    And show command "show ipv6 route" in namespace "z1" should eventually contain "2001:db8:24::/64 [110/20] via fe80::1, z1-z2"

  Scenario: The route through z3 leaves by z1-z3
    Given the test topology exists
    Then kernel route "2001:db8:34::/64" in namespace "z1" should eventually contain "via fe80::1 dev z1-z3"
    And show command "show ipv6 route" in namespace "z1" should eventually contain "2001:db8:34::/64 [110/20] via fe80::1, z1-z3"

  # OSPF's routes for z1's own networks are never selected (connected
  # wins), but each names its interface; they all read "lo", the
  # interface of the first.
  Scenario: OSPF's attached routes name their own interfaces
    Given the test topology exists
    Then show command "show ip route" in namespace "z1" should eventually contain "10.0.12.0/30 [110/10] via 0.0.0.0, z1-z2"
    And show command "show ip route" in namespace "z1" should eventually contain "10.0.13.0/30 [110/10] via 0.0.0.0, z1-z3"

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
    Then the test environment should be clean
