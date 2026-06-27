@serial
@bgp_unknown_attr_transitive
Feature: BGP unrecognized path attribute handling (RFC 4271 §9)
  As a network operator
  I want zebra-rs to follow RFC 4271 §9 for unrecognized path attributes
  So an optional transitive unknown attribute survives and propagates with
  the Partial bit set, while an optional non-transitive one is dropped.

  Test Topology (a line, all eBGP, distinct ASes):
  ```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │ i2────────────i1 │   z3    │
   │ AS65001 │                  │ AS65002 │                  │ AS65003 │
   │ .0.1    │                  │.0.2 .1.2│                  │ .1.3    │
   └─────────┘                  └─────────┘                  └─────────┘
  ```

  z1 originates 10.0.0.1/32. The debug knob `attach-unknown-attribute`
  on z1's session toward z2 stamps a synthetic unrecognized path
  attribute onto that route. Neither z2 nor z3 recognize the Type Code,
  so they exercise the receiver-side RFC 4271 §9 rules:

    * Optional Transitive (flags 0xC0) → z2 accepts it, sets the Partial
      bit, retains it, and re-advertises to z3 (which also keeps it,
      Partial still set).
    * Optional non-Transitive (flags 0x80) → z2 silently drops it; it
      never reaches z3, and the 10.0.0.1/32 route itself is unaffected.

  Config files:
  - z1-base.yaml:          z1 originates 10.0.0.1/32, no attach.
  - z1-transitive.yaml:    z1 attaches type 250, flags 0xC0, value deadbeef.
  - z1-nontransitive.yaml: z1 attaches type 251, flags 0x80, value 1234.
  - z2.yaml / z3.yaml:     plain transit / tail speakers.

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
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z2" to "192.168.1.3" should be "Established"
    And BGP session in "z3" to "192.168.1.2" should be "Established"

  Scenario: Baseline - the route propagates with no unknown attributes
    Given the test topology exists
    Then BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z2" has "10.0.0.1/32" without unknown attributes
    And BGP route in "z3" has "10.0.0.1/32"
    And BGP route in "z3" has "10.0.0.1/32" without unknown attributes

  Scenario: Optional transitive unknown attribute is retained, Partial set, and propagated
    Given the test topology exists
    When I apply config "z1-transitive.yaml" to namespace "z1"
    And I run "clear bgp ipv4 neighbor 192.168.0.2" in namespace "z1"
    And I wait 25 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    # z2 received an unrecognized OPTIONAL TRANSITIVE attribute: it MUST
    # accept it, set the Partial bit, and retain it for propagation.
    And BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z2" has "10.0.0.1/32" with unknown attribute type 250
    And BGP route in "z2" has "10.0.0.1/32" with partial unknown attribute type 250
    # z3 received it transitively from z2 - still present, Partial still set.
    And BGP route in "z3" has "10.0.0.1/32"
    And BGP route in "z3" has "10.0.0.1/32" with unknown attribute type 250
    And BGP route in "z3" has "10.0.0.1/32" with partial unknown attribute type 250

  Scenario: Optional non-transitive unknown attribute is dropped and not propagated
    Given the test topology exists
    When I apply config "z1-nontransitive.yaml" to namespace "z1"
    And I run "clear bgp ipv4 neighbor 192.168.0.2" in namespace "z1"
    And I wait 25 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    # z2 received an unrecognized OPTIONAL NON-TRANSITIVE attribute: it
    # MUST quietly ignore it. The route survives, the attribute does not.
    And BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z2" has "10.0.0.1/32" without unknown attributes
    # ... and it never reaches z3.
    And BGP route in "z3" has "10.0.0.1/32"
    And BGP route in "z3" has "10.0.0.1/32" without unknown attributes

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
