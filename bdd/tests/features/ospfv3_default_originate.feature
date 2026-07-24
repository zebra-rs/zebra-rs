@serial
@ospfv3_default_originate
Feature: OSPFv3 default-information originate advertises an AS-External default
  As a network operator
  I want `default-information originate [always]` on OSPFv3 to
  advertise an AS-External default (::/0) — unconditionally with
  `always`, or tracking a non-OSPF default route in the RIB without
  it — mirroring ospfv2_default_originate.

  Test Topology (v6 mirror):
  ```
    a -- 2001:db8:12::/64 -- b (ASBR)
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

    Then show command "show ospfv3 neighbor" in namespace "a" should contain "Full"
    And show command "show ospfv3 route" in namespace "a" should contain "::/0 metric 10"

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

    Then show command "show ospfv3 neighbor" in namespace "a" should contain "Full"
    And show command "show ospfv3 route" in namespace "a" should not contain "::/0"

    When I apply command "set router static ipv6 route ::/0 nexthop 2001:db8:12::1" in namespace "b"
    Then show command "show ospfv3 route" in namespace "a" should eventually contain "::/0"

    When I apply command "delete router static ipv6 route ::/0" in namespace "b"
    Then show command "show ospfv3 route" in namespace "a" should eventually not contain "::/0"

  Scenario: Teardown topology
    # Separate scenario so cleanup still runs when a step above fails
    # (a failed step skips the rest of its own scenario only).
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean
