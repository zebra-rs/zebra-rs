@serial
@ospf_router_id_change
Feature: OSPFv2 Router-ID set / change / delete on a live adjacency
  As a network operator
  I want zebra-rs to react correctly when an OSPFv2 instance's Router-ID is
  set, changed, or deleted while an adjacency is already up, so the peer
  re-learns the new identity, the database advertised under the old identity
  is withdrawn, and forwarding keeps working.

  Two routers on a point-to-point link, each advertising a loopback that is
  numerically distinct from any Router-ID, so a Router-ID only ever appears
  in the database as an *advertising router* (never as a stub prefix). That
  makes "the old Router-ID is gone" a clean, unambiguous assertion.

  Test Topology:
  ```
    r1 --- 10.0.12.0/30 (point-to-point, area 0.0.0.0) --- r2
       eth1                                            eth2
    loopbacks: 192.168.11.1/32 (r1)        192.168.22.1/32 (r2)
    Router-IDs: r1 starts 1.1.1.1, r2 fixed 2.2.2.2
  ```

  The bugs this guards against:
  * Every daemon boots with the constructor default Router-ID (10.0.0.1) and
    only adopts the configured value once config is applied. The LSA
    originated under the default was never withdrawn, so it lingered (and was
    even kept refreshed) as a phantom node — two routers booting as 10.0.0.1
    fought a sequence-number war and SPF failed to install transit routes,
    so even a fresh bring-up could leave loopbacks unreachable.
  * OSPFv2 keys a neighbour by its source address and only recorded the
    peer's Router-ID at neighbour creation. A peer that changed its Router-ID
    kept its OLD Router-ID in our neighbour table forever — our Router-LSA
    pointed at a node that no longer originated one, and the peer's new
    identity never entered SPF.

  Scenario: Setup point-to-point topology, reach Full and exchange loopbacks
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I connect namespace "r1" interface "eth1" to namespace "r2" interface "eth2"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    # First Hello (<=10s) + DBD/LS exchange settles well inside this.
    And I wait 30 seconds

    # Both ends are Full and see each other's starting Router-IDs.
    Then show command "show ospf neighbor" in namespace "r1" should contain "Full"
    And show command "show ospf neighbor" in namespace "r1" should contain "2.2.2.2"
    And show command "show ospf neighbor" in namespace "r2" should contain "Full"
    And show command "show ospf neighbor" in namespace "r2" should contain "1.1.1.1"
    # Loopbacks are mutually reachable: this only works once the phantom
    # default-Router-ID LSA has been withdrawn so SPF installs the transit
    # routes (it was the regression that broke even a clean bring-up).
    And ping from "r1" to "192.168.22.1" should eventually succeed
    And ping from "r2" to "192.168.11.1" should eventually succeed

  Scenario: Changing r1's Router-ID re-forms the adjacency and withdraws the old identity
    Given the test topology exists
    When I apply command "set router ospf router-id 9.9.9.9" in namespace "r1"
    And I wait 15 seconds
    # r2 re-learns r1 under the NEW Router-ID and the adjacency is Full again.
    Then show command "show ospf neighbor" in namespace "r2" should eventually contain "9.9.9.9"
    And show command "show ospf neighbor" in namespace "r2" should eventually contain "Full"
    # The OLD Router-ID 1.1.1.1 is gone from BOTH the neighbour table and
    # the link-state database (the stale self-originated LSAs were flushed,
    # not left to age out). 1.1.1.1 is never a prefix here, so its absence
    # is unambiguous.
    And show command "show ospf neighbor" in namespace "r2" should eventually not contain "1.1.1.1"
    And show command "show ospf database" in namespace "r2" should eventually not contain "1.1.1.1"
    # Forwarding still works: r1's loopback is reachable under the new identity.
    And ping from "r2" to "192.168.11.1" should eventually succeed
    And ping from "r1" to "192.168.22.1" should succeed

  Scenario: Deleting r1's Router-ID is handled gracefully and keeps forwarding
    Given the test topology exists
    When I apply command "delete router ospf router-id 9.9.9.9" in namespace "r1"
    And I wait 15 seconds
    # The previously-configured Router-ID is withdrawn; r2 re-forms under
    # whatever r1 now derives and the explicit 9.9.9.9 is gone.
    Then show command "show ospf neighbor" in namespace "r2" should eventually not contain "9.9.9.9"
    And show command "show ospf neighbor" in namespace "r2" should eventually contain "Full"
    And show command "show ospf database" in namespace "r2" should eventually not contain "9.9.9.9"
    And ping from "r2" to "192.168.11.1" should eventually succeed

  Scenario: Setting an explicit Router-ID again re-converges the adjacency
    Given the test topology exists
    When I apply command "set router ospf router-id 7.7.7.7" in namespace "r1"
    And I wait 15 seconds
    Then show command "show ospf neighbor" in namespace "r2" should eventually contain "7.7.7.7"
    And show command "show ospf neighbor" in namespace "r2" should eventually contain "Full"
    And ping from "r2" to "192.168.11.1" should eventually succeed
    And ping from "r1" to "192.168.22.1" should eventually succeed

  # Pure P2P topology (no bridge): deleting each namespace destroys the veth
  # pair, so only the daemons and namespaces need teardown.
  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    Then the test environment should be clean
