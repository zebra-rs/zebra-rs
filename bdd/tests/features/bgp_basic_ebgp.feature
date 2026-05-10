@serial
@bgp_basic_ebgp
Feature: BGP Basic Session Test on eBGP
  As a network operator
  I want to test basic BGP session establishment
  Using an isolated test topology with two zebra-rs instances with eBGP connection.

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
  ```

  Config files:
  - z1.yaml: AS 65001, peer to 192.168.0.2
  - z2.yaml: AS 65002, peer to 192.168.0.1

  Scenario: Setup topology and establish BGP session
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: Apply config change and verify BGP session drops
    Given the test topology exists
    When I apply config "z1-2.yaml" to namespace "z1"
    And I wait 1 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should not be "Established"

  Scenario: Apply config change and verify BGP session recovered
    Given the test topology exists
    When I apply config "z1-1.yaml" to namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: Advertise a network 10.0.0.1/32
    Given the test topology exists
    When I apply config "z1-3.yaml" to namespace "z1"
    And I wait 30 seconds for BGP to operate
    Then BGP route in "z2" has "10.0.0.1/32"

  Scenario: Withdraw a network 10.0.0.1/32
    Given the test topology exists
    When I apply config "z1-1.yaml" to namespace "z1"
    And I wait 1 seconds for BGP to operate
    Then BGP route in "z2" does not have "10.0.0.1/32"

  Scenario: Advertise a network 10.0.0.1/32 and 10.0.0.2/32
    Given the test topology exists
    When I apply config "z1-4.yaml" to namespace "z1"
    And I wait 30 seconds for BGP to operate
    Then BGP route in "z2" has "10.0.0.1/32" with "as_path" value "65001"
    And BGP route in "z2" has "10.0.0.1/32" with "next_hop" value "192.168.0.1"
    And BGP route in "z2" has "10.0.0.2/32"

  Scenario: Withdraw a network 10.0.0.1/32 and 10.0.0.2/32
    Given the test topology exists
    When I apply config "z1-1.yaml" to namespace "z1"
    And I wait 1 seconds for BGP to operate
    Then BGP route in "z2" does not have "10.0.0.1/32"
    And BGP route in "z2" does not have "10.0.0.2/32"

  Scenario: Apply output policy with prefix-set
    Given the test topology exists
    When I apply config "z1-5.yaml" to namespace "z1"
    And I clear namespace "z1" neighbor "192.168.0.2"
    And I wait 30 seconds for BGP to operate
    Then BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z2" does not have "10.0.0.2/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
