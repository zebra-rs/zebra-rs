@serial
@ospf_clear_neighbor
Feature: clear ospf neighbor resets an OSPFv2 adjacency
  As a network operator
  I want `clear ospf neighbor [<router-id>]` to tear an OSPFv2
  adjacency down so it re-forms from scratch — exactly like a
  dead-timer timeout — so I can force a fresh database exchange on
  demand without restarting the daemon.

  Two zebra-rs routers, o1 and o2, are joined by one point-to-point
  link and each advertise a /32 loopback into area 0.0.0.0. Once the
  adjacency is Full and the loopbacks are mutually reachable, clearing
  the neighbor must drop and rebuild the adjacency. The neighbor's
  up-time resetting is the deterministic proof that the instance was
  destroyed and re-learned rather than left untouched: had the clear
  been a no-op the up-time would keep climbing past the wait budget.

  Test Topology:
  ```
    o1 (10.0.0.1) --- 10.0.12.0/30 --- o2 (10.0.0.2)
       eth1  point-to-point  eth2
  ```

  Scenario: clear ospf neighbor destroys and re-forms the adjacency
    Given a clean test environment
    When I create namespace "o1"
    And I create namespace "o2"
    And I connect namespace "o1" interface "eth1" to namespace "o2" interface "eth2"
    And I start zebra-rs in namespace "o1"
    And I start zebra-rs in namespace "o2"
    And I apply config "o1.yaml" to namespace "o1"
    And I apply config "o2.yaml" to namespace "o2"
    # First Hello (<=10s) + DBD exchange settles well inside this; the
    # 30s also ages the adjacency so the up-time proof below has a wide
    # margin (a never-cleared neighbor would read ~55s at the check).
    And I wait 30 seconds
    # The adjacency is Full and OSPF has installed the route to o2's
    # loopback, so the /32 is reachable end-to-end.
    Then show command "show ospf neighbor" in namespace "o1" should contain "10.0.0.2"
    And show command "show ospf neighbor" in namespace "o1" should contain "Full"
    And ping from "o1" to "10.0.0.2" should succeed

    # Clear the specific neighbor by its Router-ID (the "Neighbor ID"
    # column), then let it renegotiate (next Hello <=10s + DBD, plus a
    # margin for the SPF / LSA coalescing timers).
    When I run "clear ospf neighbor 10.0.0.2" in namespace "o1"
    And I wait 25 seconds
    # It rebuilt: Full again and the loopback is reachable ...
    Then show command "show ospf neighbor" in namespace "o1" should contain "Full"
    And ping from "o1" to "10.0.0.2" should succeed
    # ... and the up-time reset to under 35s. Had the clear been a
    # no-op the neighbor would have aged ~55s by now (30 + 25 since it
    # first came up), so this bound only holds if the instance was
    # destroyed and re-learned — the deterministic teardown proof.
    And ospf neighbor "10.0.0.2" uptime in namespace "o1" should be under 35 seconds

    # The bare form (no Router-ID) clears every adjacency the same way
    # (same kill path, id = None); verify it too recovers end-to-end.
    When I run "clear ospf neighbor" in namespace "o1"
    And I wait 25 seconds
    Then show command "show ospf neighbor" in namespace "o1" should contain "Full"
    And ping from "o1" to "10.0.0.2" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "o1"
    And I stop zebra-rs in namespace "o2"
    And I delete namespace "o1"
    And I delete namespace "o2"
    Then the test environment should be clean
