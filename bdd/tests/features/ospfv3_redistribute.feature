@serial
@ospfv3_redistribute
Feature: OSPFv3 instance-level redistribute originates AS-External LSAs
  As a network operator
  I want `router ospfv3 redistribute connected` and `redistribute
  static` to originate AS-External (Type-5, 0x4005) LSAs for the
  matching IPv6 routes — previously only `redistribute bgp` existed at
  the v3 instance level — so that non-OSPF prefixes are reachable
  OSPFv3-wide.

  Two routers on a point-to-point link. b redistributes both a
  connected prefix (a dummy interface outside OSPF) and a static
  route; a must install both as external routes.

  Test Topology:
  ```
    a (10.0.0.1) -- 2001:db8:12::/64 -- b (ASBR, 10.0.0.2)
                                        dummy cafe0 2001:db8:cafe::1/64 (not in OSPF)
                                        static 2001:db8:99::/64 -> 2001:db8:12::1
                                        redistribute connected + static

    on router X the interface toward router Y is named "ethY".
    loopbacks: a 2001:db8::1/128  b 2001:db8::2/128.
  ```

  Scenario: Connected and static IPv6 routes appear as external routes on the neighbor
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    # The dummy is created after the config so the redistribute path is
    # exercised by a live AddrAdd -> RIB -> subscription event, not
    # just the initial sweep.
    And I create dummy interface "cafe0" with address "2001:db8:cafe::1/64" in namespace "b"
    And I wait 30 seconds

    Then show command "show ospfv3 neighbor" in namespace "a" should contain "Full"
    And show command "show ospfv3 neighbor" in namespace "b" should contain "Full"
    # Externally learned prefixes on a: the dummy's connected /64 and
    # the static /64, both redistributed at instance level by b.
    And show command "show ospfv3 route" in namespace "a" should contain "2001:db8:cafe::/64"
    And show command "show ospfv3 route" in namespace "a" should contain "2001:db8:99::/64"
    And show command "show ospfv3 database" in namespace "a" should contain "AS-External-LSA"

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean
