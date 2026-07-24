@serial
@ospfv2_stub_router
Feature: OSPFv2 stub-router advertisement (RFC 6987 max-metric router-lsa)
  As a network operator
  I want `max-metric router-lsa` to advertise my transit links at
  MaxLinkMetric (0xFFFF) — administratively for maintenance, or for a
  startup grace window — so neighbors route transit traffic around me
  while my own prefixes (stub links, normal cost) stay reachable.

  Test Topology (square, one area):
  ```
    r1 ---10--- r2 ---10--- r3   (via r2: cost 20 — normally wins)
     \---100--- r4 ---100---/    (via r4: cost 200 — the detour)
    r3-lo 10.0.0.3/32; the stub router under test is r2.
  ```

  Scenario: Administrative max-metric pushes transit traffic onto the detour
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I create namespace "r4"
    And I connect namespace "r1" interface "ethb" to namespace "r2" interface "etha"
    And I connect namespace "r2" interface "ethc" to namespace "r3" interface "ethb"
    And I connect namespace "r1" interface "ethd" to namespace "r4" interface "etha"
    And I connect namespace "r4" interface "ethc" to namespace "r3" interface "ethd"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I start zebra-rs in namespace "r4"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    And I apply config "r4.yaml" to namespace "r4"
    And I wait 30 seconds

    Then show command "show ospf neighbor" in namespace "r1" should contain "Full"
    And show command "show ospf" in namespace "r2" should contain "Stub router: administrative"
    # r1 detours around the stub router: r3's loopback goes via r4 at
    # cost 200 (100+100), not via r2 at 20. (Other prefixes — r2's
    # own stub networks — legitimately stay via r2 at normal cost, so
    # the assertion pins the exact route line.)
    And show command "show ospf route" in namespace "r1" should contain "10.0.0.3/32          [200] via 10.0.14.2"
    # The stub router's own prefixes stay reachable at normal cost
    # (stub links keep their metric): r2's loopback rides via r2.
    And show command "show ospf route" in namespace "r1" should contain "10.0.0.2/32          [10] via 10.0.12.2"
    And ping from "r1" to "10.0.0.2" should succeed
    And ping from "r1" to "10.0.0.3" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I stop zebra-rs in namespace "r4"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    And I delete namespace "r4"
    Then the test environment should be clean

  Scenario: on-startup max-metric expires and normal routing resumes
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I create namespace "r4"
    And I connect namespace "r1" interface "ethb" to namespace "r2" interface "etha"
    And I connect namespace "r2" interface "ethc" to namespace "r3" interface "ethb"
    And I connect namespace "r1" interface "ethd" to namespace "r4" interface "etha"
    And I connect namespace "r4" interface "ethc" to namespace "r3" interface "ethd"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I start zebra-rs in namespace "r4"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2s.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    And I apply config "r4.yaml" to namespace "r4"
    And I wait 20 seconds

    # Inside the 60s startup window: r2 is a stub router, r3's
    # loopback detours via r4 at cost 200 (eventually — the r4 leg
    # of the square may converge a few seconds later).
    Then show command "show ospf" in namespace "r2" should contain "Stub router: on-startup"
    And show command "show ospf route" in namespace "r1" should eventually contain "10.0.0.3/32          [200] via 10.0.14.2"

    # After the window expires, r2 resumes real metrics and the cheap
    # path (cost 20 via r2) returns.
    When I wait 60 seconds
    Then show command "show ospf" in namespace "r2" should not contain "Stub router"
    And show command "show ospf route" in namespace "r1" should eventually contain "10.0.0.3/32          [20] via 10.0.12.2"
    And ping from "r1" to "10.0.0.3" should succeed

  Scenario: Teardown topology
    # Separate scenario so cleanup still runs when a step above fails
    # (a failed step skips the rest of its own scenario only).
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I stop zebra-rs in namespace "r4"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    And I delete namespace "r4"
    Then the test environment should be clean
