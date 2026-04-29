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
  └────────────┬───────────────┬───────────┘
               │               │
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          └─────────┘     └─────────┘
  ```

  Config files:
  - z1-1.yaml: static IPv6 route on z1 to z2's loopback via z2's eth0 address.

  Scenario: IPv6 static route recovers after interface down/up
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with loopback "2001:db8:0:ffff::1/128" eth0 "2001:db8:1::1/64" on bridge "br0"
    And I create namespace "z2" with loopback "2001:db8:0:ffff::2/128" eth0 "2001:db8:1::2/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I wait 2 seconds
    Then ping from "z1" to "2001:db8:0:ffff::2" should succeed

    When I bring link down in namespace "z1"
    And I wait 2 seconds
    Then ping from "z1" to "2001:db8:0:ffff::2" should fail

    When I bring link up in namespace "z1"
    And I wait 3 seconds
    Then ping from "z1" to "2001:db8:0:ffff::2" should succeed
