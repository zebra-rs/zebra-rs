@isis_ipv6
@isis
Feature: IS-IS IPv6 single-topology
  As a network operator
  I want two zebra-rs instances to form an IS-IS L2 adjacency over a
  shared link, exchange IPv6 reachability via TLV 232 (link-local IIH)
  and TLV 236 (Ipv6Reach in LSPs), and install reciprocal IPv6 routes
  to each other's loopback so traffic can flow end-to-end.
  Using an isolated test topology with two zebra-rs instances connected
  via a shared bridge.

  Test Topology:
  ```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
       2001:db8:1::1/64   2001:db8:1::2/64
            (vz1ns)             (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          └─────────┘     └─────────┘
   lo: 2001:db8:0:ffff::1   lo: 2001:db8:0:ffff::2
              /128                  /128
  ```

  Config files:
  - z1-1.yaml: z1 interface addresses (lo + vz1ns) + IS-IS L2 with IPv6.
  - z2-1.yaml: z2 interface addresses (lo + vz2ns) + IS-IS L2 with IPv6.

  Scenario: Setup IS-IS L2 over a shared bridge and confirm the link is up
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with loopback and veth interface on the bridge "br0"
    And I create namespace "z2" with loopback and veth interface on the bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 20 seconds
    Then ping from "z1" to "2001:db8:1::2" should succeed
    And ping from "z2" to "2001:db8:1::1" should succeed

  Scenario: IS-IS installs reciprocal IPv6 routes to peer loopbacks
    Given the test topology exists
    Then ping from "z1" to "2001:db8:0:ffff::2" should succeed
    And ping from "z2" to "2001:db8:0:ffff::1" should succeed

  Scenario: IS-IS adjacency survives a link bounce and routes recover
    Given the test topology exists
    When I make namespace "z1" interface "vz1ns" down
    And I wait 2 seconds
    Then ping from "z1" to "2001:db8:0:ffff::2" should fail
    When I make namespace "z1" interface "vz1ns" up
    And I wait 30 seconds
    Then ping from "z1" to "2001:db8:0:ffff::2" should succeed
    And ping from "z2" to "2001:db8:0:ffff::1" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
