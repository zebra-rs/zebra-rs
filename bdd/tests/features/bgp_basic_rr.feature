@serial
@bgp_basic_rr
Feature: BGP Basic Session Test with RR
  As a network operator
  I want to test basic BGP session establishment with RR
  Using an isolated test topology with four zebra-rs instances with RR and iBGP connection.

  Test Topology:
  ```
  ┌───────────────────────────────────────────────────────────────┐
  │                             br0                               │
  └───────┬───────────────┬───────────────┬───────────────┬───────┘
          │               │               │               │
     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
     │   rr    │     │   z1    │     │   z2    │     │   z3    │
     │ AS64512 │     │ AS64512 │     │ AS64512 │     │ AS64512 │
     │  (RR)   │     │(client) │     │(client) │     │(client) │
     │192.168. │     │192.168. │     │192.168. │     │192.168. │
     │  0.1/24 │     │  0.2/24 │     │  0.3/24 │     │  0.4/24 │
     └─────────┘     └─────────┘     └─────────┘     └─────────┘
  ```

  Config files:
  - rr.yaml: AS 64512, route-reflector with z1/z2/z3 as clients
  - z1.yaml: AS 64512, peer to RR (z1-network.yaml adds network 10.0.0.1/32)
  - z2.yaml: AS 64512, peer to RR
  - z3.yaml: AS 64512, peer to RR

  Scenario: Setup topology and establish BGP session
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "rr" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z1" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.3/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.4/24" on bridge "br0"
    And I start zebra-rs in namespace "rr"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "rr.yaml" to namespace "rr"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "rr" to "192.168.0.2" should eventually be "Established"
    And BGP session in "rr" to "192.168.0.3" should eventually be "Established"
    And BGP session in "rr" to "192.168.0.4" should eventually be "Established"

  Scenario: A client route is reflected to the other clients with next-hop unchanged
    Given the test topology exists
    When I apply config "z1-network.yaml" to namespace "z1"
    # Two advertisement hops (z1 -> rr, rr -> clients); the proven RR
    # timing in bgp_rr_ebgp_strip waits 15s before asserting reflection.
    And I wait 15 seconds for BGP to operate
    Then BGP route in "z2" has "10.0.0.1/32" with "next_hop" value "192.168.0.2"
    And BGP route in "z3" has "10.0.0.1/32" with "next_hop" value "192.168.0.2"

  Scenario: Withdrawing the client route removes it from the other clients
    Given the test topology exists
    When I apply config "z1.yaml" to namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" does not have "10.0.0.1/32"
    And BGP route in "z3" does not have "10.0.0.1/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "rr"
    And I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "rr"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
