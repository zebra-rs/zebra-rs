@serial
@rib_static_ipv6
Feature: RIB IPv6 static route
  As a network operator
  I want IPv6 static routes to recover after the egress interface goes
  down and back up.
  Using an isolated test topology with two zebra-rs instances connected
  via a shared bridge.

  Test Topology:
  ```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  │                                        │
  └────────────┬───────────────┬───────────┘
               │               │
       2001:db8:1::1/64   2001:db8:1::2/64
            (vz1ns)            (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          └─────────┘     └─────────┘
   lo: 2001:db8:0:ffff::1   lo: 2001:db8:0:ffff::2
              /128                  /128
  ```

  Config files:
  - z1-1.yaml: z1 interface addresses (lo + vz1ns).
  - z2-1.yaml: z2 interface addresses (lo + vz2ns).
  - z1-2.yaml: static IPv6 route on z1 to z2's loopback via z2's eth0 address.

  Scenario: Setup topology for IPv6 loopback and veth address.
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with loopback and veth interface on the bridge "br0"
    And I create namespace "z2" with loopback and veth interface on the bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 2 seconds
    Then ping from "z1" to "2001:db8:1::2" should succeed

  Scenario: Apply IPv6 static route and verify ping to z2's loopback.
    Given the test topology exists
    When I apply config "z1-2.yaml" to namespace "z1"
    And I wait 2 seconds
    Then ping from "z1" to "2001:db8:0:ffff::2" should succeed

  Scenario: Egress interface goes down — static route is invalidated.
    Given the test topology exists
    When I make namespace "z1" interface "vz1ns" down
    And I wait 2 seconds
    Then ping from "z1" to "2001:db8:0:ffff::2" should fail

  Scenario: Egress interface comes back up — static route recovers.
    Given the test topology exists
    When I make namespace "z1" interface "vz1ns" up
    And I wait 3 seconds
    Then ping from "z1" to "2001:db8:0:ffff::2" should succeed

  Scenario: Bounce egress interface again — recovery is repeatable.
    Given the test topology exists
    When I make namespace "z1" interface "vz1ns" down
    And I wait 2 seconds
    Then ping from "z1" to "2001:db8:0:ffff::2" should fail
    When I make namespace "z1" interface "vz1ns" up
    And I wait 3 seconds
    Then ping from "z1" to "2001:db8:0:ffff::2" should succeed
