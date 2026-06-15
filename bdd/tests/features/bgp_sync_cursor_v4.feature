@serial
@bgp_sync_cursor_v4
Feature: BGP IPv4-unicast resumable session-up sync cursor (Tier 1a)

  Exercises the ZEBRA_BGP_SYNC_CHUNK resumable cursor: the device under
  test z2 runs with sync chunk 1, so its session-up IPv4-unicast dump to
  a late peer runs one prefix per main-loop tick instead of one
  uninterruptible pass. Pins that the chunked dump still delivers every
  route, sends EoR, registers each route in adj_out (so a later withdraw
  + peer-down reach the synced peer), and matches the legacy one-shot
  result.

  Test Topology:
  ```
  z1 (AS65001) ── z2 (AS65002, sync chunk 1) ── z3 (AS65003)  late peer → cursor sync
   origin          device under test            recv
  ```
  z1 originates 10.1.0.0/24, 10.2.0.0/24, 10.3.0.0/24. All on bridge br0.

  Scenario: z1 and the cursor device z2 come up; z2 holds the routes
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2" with sync chunk 1
    And I apply config "z1-routes.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And show command "show bgp ipv4" in namespace "z2" should contain "10.1.0.0/24"
    And show command "show bgp ipv4" in namespace "z2" should contain "10.2.0.0/24"
    And show command "show bgp ipv4" in namespace "z2" should contain "10.3.0.0/24"

  Scenario: the late peer z3 gets every route via the chunked cursor
    Given the test topology exists
    When I start zebra-rs in namespace "z3"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 15 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.3" should be "Established"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.1.0.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.2.0.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.3.0.0/24"

  Scenario: z1 withdraws one route; the withdraw reaches the cursor-synced peer z3
    Given the test topology exists
    When I apply config "z1-withdraw.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp ipv4" in namespace "z3" should not contain "10.1.0.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.2.0.0/24"
    And show command "show bgp ipv4" in namespace "z3" should contain "10.3.0.0/24"

  Scenario: z1's session drops; the peer-down sweep clears its routes from z3
    Given the test topology exists
    Then show command "show bgp ipv4" in namespace "z3" should contain "10.2.0.0/24"
    When I stop zebra-rs in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should not be "Established"
    And show command "show bgp ipv4" in namespace "z3" should not contain "10.2.0.0/24"
    And show command "show bgp ipv4" in namespace "z3" should not contain "10.3.0.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
