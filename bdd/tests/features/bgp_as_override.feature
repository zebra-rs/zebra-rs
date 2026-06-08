@serial
@bgp_as_override
Feature: BGP as-override rewrites the peer AS on egress so a shared-AS neighbor accepts the route
  As a network operator
  I want `neighbor X as-override`
  So a neighbor that reuses an AS already in the AS_PATH still accepts my routes.

  Test Topology (a line, where z1 and z3 share AS 65001):
  ```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │ i2────────────i1 │   z3    │
   │ AS65001 │                  │ AS65002 │                  │ AS65001 │
   │ .0.1    │                  │.0.2 .1.2│                  │ .1.3    │
   └─────────┘                  └─────────┘                  └─────────┘
  ```

  z1 originates 10.0.0.1/32. It reaches z2 with AS_PATH "65001". When z2
  re-advertises it to z3 it would normally prepend its own AS, giving
  "65002 65001"; because z3 is also AS 65001 the RFC 4271 loop check
  drops it. With `as-override` on z2's session toward z3, z2 first
  rewrites z3's AS (65001) in the path to its own (65002), so z3 sees
  "65002 65002" and accepts the route. This is the send-side counterpart
  to `allowas-in`.

  Config files:
  - z1.yaml:           z1 originates 10.0.0.1/32
  - z3.yaml:           z3 plain (strict loop check, no allowas-in)
  - z2-base.yaml:      z2 without as-override
  - z2-override.yaml:  z2 with `as-override` toward 192.168.1.3

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
    And I apply config "z2-base.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z2" to "192.168.1.3" should be "Established"
    And BGP session in "z3" to "192.168.1.2" should be "Established"

  Scenario: Without as-override the RFC 4271 loop check drops the route at z3
    Given the test topology exists
    # z2 has it (learned from z1), but z3 drops it because its own AS
    # 65001 is in the AS_PATH "65002 65001".
    Then BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z3" does not have "10.0.0.1/32"

  Scenario: as-override rewrites z3's AS on egress so z3 accepts the route
    Given the test topology exists
    When I apply config "z2-override.yaml" to namespace "z2"
    # Bounce the z2<->z3 session so z2 re-advertises 10.0.0.1/32 with the
    # overridden AS_PATH "65002 65002".
    And I run "clear bgp ipv4 neighbor 192.168.1.3" in namespace "z2"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z3" to "192.168.1.2" should be "Established"
    And BGP route in "z3" has "10.0.0.1/32"
    And show command "show ip bgp neighbors" in namespace "z2" should contain "AS-Override"

  # Pure P2P topology (no bridge): deleting each namespace destroys the veth
  # pair ends it holds, so only the daemons and namespaces need teardown.
  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    Then the test environment should be clean
