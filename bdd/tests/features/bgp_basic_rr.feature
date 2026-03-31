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
  - rr.yaml: AS 64512, peer to all BGP speakcer
  - z1.yaml: AS 64512, peer to RR
  - z2.yaml: AS 64512, peer to RR
  - z3.yaml: AS 64512, peer to RR

  Scenario: Setup topology and establish BGP session
    Given a clean test environment
    When I create bridge "br0"
    And I setup instace
    | rr | 192.168.0.1/24 | br0 |
    | z1 | 192.168.0.2/24 | br0 |
    | z2 | 192.168.0.3/24 | br0 |
    | z3 | 192.168.0.4/24 | br0 |

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
