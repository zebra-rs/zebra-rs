@serial
@pim_adjacency
Feature: PIM-SM two-router neighborship forms on a point-to-point link
  As a network operator
  I want two zebra-rs PIM routers joined by a veth link to discover
  each other through Hellos and elect the Designated Router, so the
  PIM-SM neighbor plane (Hello options, holdtime, DR priority) is
  exercised router-to-router.

  p1 advertises DR priority 200, p2 the default-equivalent 1. With
  priority-based election the LOWER address 10.1.12.1 must win DR —
  proving the election used the DR-Priority option and not the
  highest-address fallback.

  Test Topology:
  ```
    p1 (10.1.12.1/24, DR prio 200) --- veth --- p2 (10.1.12.2/24, DR prio 1)
       eth1                                        eth2
  ```

  Scenario: Two PIM routers discover each other and elect the DR
    Given a clean test environment
    When I create namespace "p1"
    And I create namespace "p2"
    And I connect namespace "p1" interface "eth1" to namespace "p2" interface "eth2"
    And I start zebra-rs in namespace "p1"
    And I start zebra-rs in namespace "p2"
    And I apply config "p1.yaml" to namespace "p1"
    And I apply config "p2.yaml" to namespace "p2"

    # Triggered Hellos at enable make discovery near-immediate.
    Then show command "show pim neighbor" in namespace "p1" should eventually contain "10.1.12.2"
    And show command "show pim neighbor" in namespace "p2" should eventually contain "10.1.12.1"

    # Both interfaces run PIM.
    And show command "show pim interface" in namespace "p1" should contain "Up"
    And show command "show pim interface" in namespace "p2" should contain "Up"

    # DR on the link is 10.1.12.1 (priority 200 beats the higher
    # address). On p2 that address can only appear in the DR column.
    And show command "show pim interface" in namespace "p2" should eventually contain "10.1.12.1"

  Scenario: Teardown topology
    When I stop zebra-rs in namespace "p1"
    And I stop zebra-rs in namespace "p2"
    And I delete namespace "p1"
    And I delete namespace "p2"
    Then the test environment should be clean
