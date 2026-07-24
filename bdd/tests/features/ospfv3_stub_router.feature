@serial
@ospfv3_stub_router
Feature: OSPFv3 stub-router advertisement (RFC 5340 R-bit clear)
  As a network operator
  I want `max-metric router-lsa` on OSPFv3 to clear the R and V6
  option bits in my Router-LSAs (ospf6d's `stub-router`) so
  neighbors exclude me from transit paths (RFC 5340 §4.8.1) while my
  own prefixes stay reachable — the v3 counterpart of v2's
  RFC 6987 MaxLinkMetric.

  Test Topology (square, one area — v6 mirror of ospfv2_stub_router):
  ```
    r1 ---10--- r2 ---10--- r3   (via r2: cost 20 — normally wins)
     \---100--- r4 ---100---/    (via r4: cost 200 — the detour)
    r3-lo 2001:db8::3/128; the stub router under test is r2.
  ```

  Scenario: Administrative R-bit clear pushes transit traffic onto the detour
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

    Then show command "show ospfv3 neighbor" in namespace "r1" should contain "Full"
    And show command "show ospfv3" in namespace "r2" should contain "Stub router: administrative"
    # r1 detours around the stub router: r3's loopback rides the
    # 200-cost r4 path, not the 20-cost r2 path.
    And show command "show ospfv3 route" in namespace "r1" should eventually contain "2001:db8::3/128 metric 200 via"
    # The stub router's own loopback stays reachable through it at
    # normal cost — its prefixes anchor at the (reachable) vertex.
    And show command "show ospfv3 route" in namespace "r1" should contain "2001:db8::2/128 metric 10 via"
    And ping from "r1" to "2001:db8::2" should succeed
    And ping from "r1" to "2001:db8::3" should succeed

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

  Scenario: on-startup R-bit clear expires and the cheap path returns
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

    # Inside the 60s startup window: detour via r4.
    Then show command "show ospfv3" in namespace "r2" should contain "Stub router: on-startup"
    And show command "show ospfv3 route" in namespace "r1" should eventually contain "2001:db8::3/128 metric 200 via"

    # After the window expires, normal options resume and the cheap
    # path returns.
    When I wait 60 seconds
    Then show command "show ospfv3" in namespace "r2" should not contain "Stub router"
    And show command "show ospfv3 route" in namespace "r1" should eventually contain "2001:db8::3/128 metric 20 via"
    And ping from "r1" to "2001:db8::3" should succeed

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
