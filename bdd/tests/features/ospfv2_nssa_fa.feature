@serial
@ospfv2_nssa_fa
Feature: NSSA Type-7 forwarding address is originated, translated, and resolved
  As a network operator
  I want NSSA ASBRs to originate P-bit Type-7 LSAs with a non-zero
  forwarding address (RFC 3101 §2.3), the ABR to preserve it when
  translating to Type-5 (or zero it under `nssa-suppress-fa`), and
  backbone receivers to resolve the external route via the FA's
  intra/inter-area path (RFC 2328 §16.4 step 3) — previously such
  LSAs were skipped entirely.

  Test Topology:
  ```
     backbone            NSSA area 0.0.0.1
    b -- 10.0.12.0/30 -- a (ABR/translator) -- 10.0.13.0/30 -- c (ASBR)
                                          dummy on c: 10.9.9.0/24
    Type-7 from c carries FA 10.0.13.2 (c's NSSA interface); b's
    route to the external exists ONLY if it can resolve that FA via
    its inter-area route to 10.0.13.0/30.
  ```

  Scenario: FA-carrying external resolves on the backbone end to end
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I connect namespace "a" interface "ethc" to namespace "c" interface "etha"
    And I create dummy interface "d9" with address "10.9.9.1/24" in namespace "c"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "c"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "c.yaml" to namespace "c"
    And I wait 30 seconds

    Then show command "show ospf neighbor" in namespace "b" should contain "Full"
    # The FA's covering prefix reaches b as an inter-area route...
    And show command "show ospf route" in namespace "b" should contain "10.0.13.0/30"
    # ...so the FA-carrying translated Type-5 resolves and installs.
    And show command "show ospf route" in namespace "b" should eventually contain "10.9.9.0/24"
    And show command "show ospf route" in namespace "b" should contain "[20]"
    And ping from "b" to "10.9.9.1" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "c"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "c"
    Then the test environment should be clean

  Scenario: nssa-suppress-fa zeroes the FA and routing still works via the ABR
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I connect namespace "a" interface "ethc" to namespace "c" interface "etha"
    And I create dummy interface "d9" with address "10.9.9.1/24" in namespace "c"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "c"
    And I apply config "a_suppress.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "c.yaml" to namespace "c"
    And I wait 30 seconds

    # With the FA suppressed the Type-5 falls back to via-the-ABR
    # semantics — the route must still install and forward.
    Then show command "show ospf route" in namespace "b" should eventually contain "10.9.9.0/24"
    And ping from "b" to "10.9.9.1" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "c"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "c"
    Then the test environment should be clean
