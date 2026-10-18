@ospf_lan_dr_election
@ospf
Feature: OSPF elects a DR and a BDR on a broadcast network
  As a network operator
  I want the routers on a broadcast network to agree on a Designated
  Router and a Backup Designated Router (RFC 2328 §9.4, RFC 5340
  §4.2.2), so every router keeps a full adjacency with both and the BDR
  takes over at once when the DR fails.

  The election needs every router's Hello to declare the DR and BDR it
  has elected. OSPFv2 Hellos used to declare neither: the other routers
  then elected the DR as their BDR too, r2 never became BDR, and r1 and
  r2 never formed an adjacency. OSPFv3 Hellos always declared them; the
  feature checks both versions on the same network.

  Test Topology:
  ```
    r1 (10.0.0.1)    r2 (10.0.0.2)    r3 (10.0.0.3)
         |                |                |
    ------------------- sw (bridge) -------------------
      192.168.10.0/24 and 2001:db8:10::/64, router rN at .N / ::N
  ```

  All three run OSPFv2 and OSPFv3 at the default priority, so the
  highest Router ID, r3, becomes DR and r2 BDR. When r3 goes, r2 takes
  over as DR and r1 becomes BDR.

  Scenario: Build the broadcast network
    Given a clean test environment
    When I create namespace "sw"
    And I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I connect namespace "r1" interface "r1-sw" to namespace "sw" interface "sw-r1"
    And I connect namespace "r2" interface "r2-sw" to namespace "sw" interface "sw-r2"
    And I connect namespace "r3" interface "r3-sw" to namespace "sw" interface "sw-r3"
    And I execute "ip link add br0 type bridge mcast_snooping 0" in namespace "sw"
    And I execute "ip link set br0 up" in namespace "sw"
    And I execute "ip link set sw-r1 master br0" in namespace "sw"
    And I execute "ip link set sw-r2 master br0" in namespace "sw"
    And I execute "ip link set sw-r3 master br0" in namespace "sw"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    # No router elects before its Wait timer (the 40 s dead interval)
    # fires, by which time all three have heard each other. Each
    # router's election then reaches the others with its next Hello, so
    # the roles settle a few Hello intervals later.
    And I wait 45 seconds
    Then show command "show ospf neighbor" in namespace "r3" should eventually contain "10.0.0.1"
    And show command "show ospf neighbor" in namespace "r3" should eventually contain "10.0.0.2"
    And show command "show ospfv3 neighbor" in namespace "r3" should eventually contain "10.0.0.1"
    And show command "show ospfv3 neighbor" in namespace "r3" should eventually contain "10.0.0.2"

  Scenario: The highest Router ID is DR and the next is BDR
    Given the test topology exists
    # OSPFv2: every router names r3 DR and r2 BDR, by Router ID and
    # interface address.
    Then show command "show ospf interface" in namespace "r3" should eventually contain "State DR, Priority"
    And show command "show ospf interface" in namespace "r2" should eventually contain "State Backup, Priority"
    And show command "show ospf interface" in namespace "r1" should eventually contain "State DROther, Priority"
    And show command "show ospf interface" in namespace "r1" should eventually contain "Designated Router (ID) 10.0.0.3 Interface Address 192.168.10.3/24"
    And show command "show ospf interface" in namespace "r1" should eventually contain "Backup Designated Router (ID) 10.0.0.2, Interface Address 192.168.10.2/24"
    And show command "show ospf interface" in namespace "r3" should eventually contain "Backup Designated Router (ID) 10.0.0.2, Interface Address 192.168.10.2/24"
    # r1 keeps a full adjacency with the DR and with the BDR.
    And show command "show ospf neighbor" in namespace "r1" should eventually contain "Full/DR"
    And show command "show ospf neighbor" in namespace "r1" should eventually contain "Full/Backup"
    And show command "show ospf neighbor" in namespace "r3" should eventually contain "Full/Backup"
    # OSPFv3: the same election.
    And show command "show ospfv3 interface" in namespace "r3" should eventually contain "state DR, neighbors 2"
    And show command "show ospfv3 interface" in namespace "r2" should eventually contain "state Backup, neighbors 2"
    And show command "show ospfv3 interface" in namespace "r1" should eventually contain "state DROther, neighbors 2"
    And show command "show ospfv3 interface" in namespace "r1" should eventually contain "DR: 10.0.0.3  BDR: 10.0.0.2"

  Scenario: The BDR takes over when the DR fails
    Given the test topology exists
    When I stop zebra-rs in namespace "r3"
    # r1 and r2 notice when the 40 s dead interval runs out.
    And I wait 45 seconds
    # OSPFv2: r2 becomes DR and r1, the only other router left, BDR.
    Then show command "show ospf interface" in namespace "r2" should eventually contain "State DR, Priority"
    And show command "show ospf interface" in namespace "r1" should eventually contain "State Backup, Priority"
    And show command "show ospf interface" in namespace "r1" should eventually contain "Designated Router (ID) 10.0.0.2 Interface Address 192.168.10.2/24"
    And show command "show ospf interface" in namespace "r2" should eventually contain "Backup Designated Router (ID) 10.0.0.1, Interface Address 192.168.10.1/24"
    And show command "show ospf neighbor" in namespace "r1" should eventually contain "Full/DR"
    # OSPFv3: the same.
    And show command "show ospfv3 interface" in namespace "r2" should eventually contain "state DR, neighbors 1"
    And show command "show ospfv3 interface" in namespace "r1" should eventually contain "state Backup, neighbors 1"
    And show command "show ospfv3 interface" in namespace "r1" should eventually contain "DR: 10.0.0.2  BDR: 10.0.0.1"

  Scenario: Teardown topology
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    And I delete namespace "sw"
    Then the test environment should be clean
