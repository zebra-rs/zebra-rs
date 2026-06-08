@serial
@bgp_allowas_in
Feature: BGP allowas-in relaxes the inbound AS_PATH loop check
  As a network operator
  I want `neighbor X allowas-in [count <1-10>|origin]`
  So a neighbor can accept routes whose AS_PATH already contains my AS.

  Test Topology (a line, where z1 and z3 share AS 65001):
  ```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │ i2────────────i1 │   z3    │
   │ AS65001 │                  │ AS65002 │                  │ AS65001 │
   │ .0.1    │                  │.0.2 .1.2│                  │ .1.3    │
   └─────────┘                  └─────────┘                  └─────────┘
  ```

  z1 originates 10.0.0.1/32. It reaches z2 with AS_PATH "65001", and z2
  re-advertises it to z3 with AS_PATH "65002 65001". Because z3 is also
  AS 65001, the RFC 4271 inbound loop check drops it — unless z3 has
  `allowas-in` configured on the session toward z2.

  Config files:
  - z1.yaml / z2.yaml: static line topology, z1 originates 10.0.0.1/32
  - z3-base.yaml:    z3 without allowas-in (strict loop check)
  - z3-allowas.yaml: z3 with bare `allowas-in` (default count 3)
  - z3-origin.yaml:  z3 with `allowas-in origin`

  Scenario: Setup line topology and establish all sessions
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I create namespace "z3"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I connect namespace "z2" interface "i2" to namespace "z3" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3-base.yaml" to namespace "z3"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z2" to "192.168.1.3" should be "Established"
    And BGP session in "z3" to "192.168.1.2" should be "Established"

  Scenario: Default RFC 4271 loop check drops the route at z3
    Given the test topology exists
    # z2 has it (so propagation reached the relay), but z3 drops it
    # because its own AS 65001 is in the AS_PATH.
    Then BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z3" does not have "10.0.0.1/32"

  Scenario: allowas-in lets z3 accept the looped route
    Given the test topology exists
    When I apply config "z3-allowas.yaml" to namespace "z3"
    And I clear namespace "z3" neighbor "192.168.1.2"
    And I wait 15 seconds for BGP to operate
    Then BGP route in "z3" has "10.0.0.1/32"
    And show command "show ip bgp neighbors" in namespace "z3" should contain "Allowas-in: 3 occurrence(s)"

  Scenario: allowas-in origin mode accepts the route and shows in neighbor output
    Given the test topology exists
    When I apply config "z3-origin.yaml" to namespace "z3"
    And I clear namespace "z3" neighbor "192.168.1.2"
    And I wait 15 seconds for BGP to operate
    Then BGP route in "z3" has "10.0.0.1/32"
    And show command "show ip bgp neighbors" in namespace "z3" should contain "Allowas-in: origin"
