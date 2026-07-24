@serial
@ospfv2_default_originate
Feature: OSPFv2 default-information originate advertises a Type-5 default
  As a network operator
  I want `default-information originate [always]` to advertise a
  Type-5 default route (0.0.0.0/0) — unconditionally with `always`,
  or tracking the presence of a non-OSPF default route in the RIB
  without it — so downstream routers follow the ASBR for everything
  off-net.

  Test Topology:
  ```
    a (10.0.0.1) -- 10.0.12.0/30 -- b (ASBR, 10.0.0.2)
                                    default-information originate
  ```

  Scenario: always originates unconditionally at the configured metric
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b_always.yaml" to namespace "b"
    And I wait 30 seconds

    Then show command "show ospf neighbor" in namespace "a" should contain "Full"
    # The default at the FRR-parity metric 10, E2.
    And show command "show ospf route" in namespace "a" should contain "0.0.0.0/0"
    And show command "show ospf route" in namespace "a" should contain "[10]"

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean

  Scenario: Without always, the default tracks a non-OSPF default route in the RIB
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b_cond.yaml" to namespace "b"
    And I wait 30 seconds

    Then show command "show ospf neighbor" in namespace "a" should contain "Full"
    # No default route in b's RIB yet -> nothing advertised.
    And show command "show ospf route" in namespace "a" should not contain "0.0.0.0/0"

    # A static default appears in b's RIB: the RIB default watch fires
    # and the Type-5 default is originated.
    When I apply command "set router static ipv4 route 0.0.0.0/0 nexthop 10.0.12.1" in namespace "b"
    Then show command "show ospf route" in namespace "a" should eventually contain "0.0.0.0/0"

    # Withdraw the static default: the Type-5 default is flushed.
    When I apply command "delete router static ipv4 route 0.0.0.0/0" in namespace "b"
    Then show command "show ospf route" in namespace "a" should eventually not contain "0.0.0.0/0"

  Scenario: Teardown topology
    # Separate scenario so cleanup still runs when a step above fails
    # (a failed step skips the rest of its own scenario only).
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean
