@serial
@ospfv3_instance_id
Feature: OSPFv3 Instance ID separates instances on a link (RFC 5340)
  As a network operator
  I want the per-interface `instance-id` to be stamped into every
  OSPFv3 packet header (RFC 5340 §A.3.1) and enforced on receive
  (§8.2: drop on mismatch) — so multiple OSPFv3 instances can share
  one link without forming cross-instance adjacencies.

  Test Topology:
  ```
    a (10.0.0.1) -- 2001:db8:12::/64 -- b (10.0.0.2)
    matched scenario: both interfaces instance-id 5
    mismatch scenario: a=5, b=7 — no adjacency may form
  ```

  Scenario: Matching non-zero instance IDs form a normal adjacency
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I wait 25 seconds

    Then show command "show ospfv3 interface" in namespace "a" should contain "Instance ID: 5"
    And show command "show ospfv3 neighbor" in namespace "a" should contain "Full"
    And show command "show ospfv3 neighbor" in namespace "b" should contain "Full"
    And show command "show ospfv3 route" in namespace "a" should contain "2001:db8::2/128"
    And ping from "a" to "2001:db8::2" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean

  Scenario: Mismatched instance IDs never form an adjacency
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b_mismatch.yaml" to namespace "b"
    And I wait 25 seconds

    # Each side drops the other's packets (instance 5 vs 7): no
    # neighbor entry may exist in either direction.
    Then show command "show ospfv3 neighbor" in namespace "a" should not contain "10.0.0.2"
    And show command "show ospfv3 neighbor" in namespace "b" should not contain "10.0.0.1"
    And show command "show ospfv3 route" in namespace "a" should not contain "2001:db8::2/128"

  Scenario: Teardown topology
    # Separate scenario so cleanup still runs when a step above fails
    # (a failed step skips the rest of its own scenario only).
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean
