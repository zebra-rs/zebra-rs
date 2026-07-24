@serial
@ospfv3_adjacency
Feature: OSPFv3 two-router adjacency forms over a point-to-point link
  As a network operator
  I want two zebra-rs OSPFv3 routers joined by a point-to-point link to
  progress all the way to Full and synchronise their databases, so the
  OSPFv3 control plane is exercised router-to-router (not only against
  an external implementation).

  This is the v3 counterpart of `ospf_clear_neighbor` and guards the
  OSPFv3 half of the adjacency-formation fixes (Router-ID config applied
  per instance, `addr_add` re-firing InterfaceUp, and the DB-exchange
  More-bit being cleared). Without those, two zebra-rs v3 routers share
  the default Router-ID 10.0.0.1 and/or stall in Exchange and never reach
  Full — a regression invisible to zebra-rs<->FRR validation and to CI
  (which does not run the BDD suite).

  Reaching Full in BOTH directions is the proof: it requires the master
  (higher Router-ID, o2) and the slave (o1) to complete ExStart ->
  Exchange -> Loading -> Full, which only happens when all three fixes
  hold.

  Test Topology:
  ```
    o1 (router-id 10.0.0.1) --- 2001:db8:12::/64 --- o2 (router-id 10.0.0.2)
       eth1   point-to-point, area 0.0.0.0   eth2
    loopbacks: 2001:db8::1/128 (o1)         2001:db8::2/128 (o2)
  ```

  Scenario: Two OSPFv3 routers reach Full over a point-to-point link
    Given a clean test environment
    When I create namespace "o1"
    And I create namespace "o2"
    And I connect namespace "o1" interface "eth1" to namespace "o2" interface "eth2"
    And I start zebra-rs in namespace "o1"
    And I start zebra-rs in namespace "o2"
    And I apply config "o1.yaml" to namespace "o1"
    And I apply config "o2.yaml" to namespace "o2"
    # First Hello (<=10s) + DBD/LS exchange settles well inside this.
    And I wait 30 seconds

    # o1 (slave) sees o2 (master) Full.
    Then show command "show ospfv3 neighbor" in namespace "o1" should contain "10.0.0.2"
    And show command "show ospfv3 neighbor" in namespace "o1" should contain "Full"
    # o2 (master) sees o1 (slave) Full — both ends complete the exchange.
    And show command "show ospfv3 neighbor" in namespace "o2" should contain "10.0.0.1"
    And show command "show ospfv3 neighbor" in namespace "o2" should contain "Full"

  Scenario: Teardown topology
    # Separate scenario so cleanup still runs when a step above fails
    # (a failed step skips the rest of its own scenario only).
    When I stop zebra-rs in namespace "o1"
    And I stop zebra-rs in namespace "o2"
    And I delete namespace "o1"
    And I delete namespace "o2"
    Then the test environment should be clean
