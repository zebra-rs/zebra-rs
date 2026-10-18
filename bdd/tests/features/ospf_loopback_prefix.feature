@ospf_loopback_prefix
@ospf
Feature: OSPF never advertises the loopback address
  As a network operator
  I want OSPF to advertise the addresses I configure on `lo` but never
  the loopback address the kernel puts there itself — 127.0.0.1/8 and
  ::1/128 must not leave the node (RFC 1122 §3.2.1.3, RFC 4291 §2.5.3).

  OSPFv3 used to advertise ::1/128 in every router's
  Intra-Area-Prefix-LSA and lo's Link-LSA whenever lo was enabled, and
  installed it as a route of its own. OSPFv2 already left out
  127.0.0.0/8; the feature checks both versions.

  Test Topology:
  ```
    r1 (10.0.0.1, 2001:db8::1) ---- r2 (10.0.0.2, 2001:db8::2)
        192.168.12.0/24 and 2001:db8:12::/64, point-to-point
  ```

  Scenario: Build the topology
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I connect namespace "r1" interface "r1-r2" to namespace "r2" interface "r2-r1"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    Then show command "show ospf neighbor" in namespace "r1" should eventually contain "Full"
    And show command "show ospfv3 neighbor" in namespace "r1" should eventually contain "Full"

  Scenario: OSPFv3 advertises the configured loopback but not ::1
    Given the test topology exists
    # r2's configured loopback reaches r1 in r2's Intra-Area-Prefix-LSA,
    # the LSA that used to carry ::1/128 as well.
    Then show command "show ospfv3 database detail" in namespace "r1" should eventually contain "Prefix: 2001:db8::2/128"
    And show command "show ospfv3 database detail" in namespace "r1" should not contain "Prefix: ::1/128"
    And show command "show ospfv3 database detail" in namespace "r2" should eventually contain "Prefix: 2001:db8::1/128"
    And show command "show ospfv3 database detail" in namespace "r2" should not contain "Prefix: ::1/128"
    # Nor does OSPFv3 install ::1/128 as a route.
    And show command "show ospfv3 route" in namespace "r1" should eventually contain "2001:db8::2/128 metric"
    And show command "show ospfv3 route" in namespace "r1" should not contain "  ::1/128 metric"
    And show command "show ospfv3 route" in namespace "r1" should contain "2001:db8::1/128 metric 0 directly attached to lo"

  Scenario: OSPFv2 advertises the configured loopback but not 127.0.0.0/8
    Given the test topology exists
    Then show command "show ospf database detail" in namespace "r1" should eventually contain "Network/subnet number: 10.0.0.2"
    And show command "show ospf database detail" in namespace "r1" should not contain "Network/subnet number: 127."
    And show command "show ospf route" in namespace "r1" should eventually contain "10.0.0.2/32"
    And show command "show ospf route" in namespace "r1" should not contain "127.0.0.0/8"
    # lo is shown with its configured address, not the kernel's 127.0.0.1/8.
    And show command "show ospf interface" in namespace "r1" should contain "Internet Address 10.0.0.1/32"

  Scenario: Teardown topology
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    Then the test environment should be clean
