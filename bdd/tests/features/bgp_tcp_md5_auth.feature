@serial
@bgp_tcp_md5_auth
Feature: BGP TCP MD5 Authentication (RFC 2385)
  As a network operator
  I want to protect a BGP session with a TCP MD5 shared secret and
  verify that mismatched secrets prevent the session from coming up.

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
  - z1-1.yaml: AS 65001, tcp-md5 password "shared-md5-secret".
  - z2-1.yaml: AS 65002, tcp-md5 password "shared-md5-secret" (match).
  - z2-2.yaml: AS 65002, tcp-md5 password "WRONG-md5-secret"
    (mismatch — peer's kernel silently drops SYNs).

  Scenario: Establish a TCP MD5 authenticated BGP session
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

  Scenario: Mismatched password drops the session
    Given the test topology exists
    When I apply config "z2-2.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should not be "Established"
    And BGP session in "z2" to "192.168.0.1" should not be "Established"

  Scenario: Restoring the matching password re-establishes the session
    Given the test topology exists
    When I apply config "z2-1.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
