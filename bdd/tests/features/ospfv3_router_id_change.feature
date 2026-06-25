@serial
@ospfv3_router_id_change
Feature: OSPFv3 Router-ID change on a live adjacency
  As a network operator
  I want zebra-rs to withdraw the LSAs advertised under an OSPFv3 instance's
  old Router-ID when that Router-ID changes on a running adjacency, so a
  stale identity does not linger in every router's database until MaxAge.

  Two OSPFv3 routers on a point-to-point link. OSPFv3 keys a neighbour by
  Router-ID (RFC 5340 §10), so when o1's Router-ID changes o2 naturally
  forms a fresh neighbour and the old one ages out on its dead timer. The
  part that needs a fix is the database: the LSAs o1 originated under the
  old Router-ID would otherwise survive as a phantom node. A Router-ID is
  numerically distinct from any IPv6 prefix here, so "the old Router-ID is
  gone from the database" is an unambiguous assertion.

  Test Topology:
  ```
    o1 --- 2001:db8:12::/64 (point-to-point, area 0.0.0.0) --- o2
       eth1                                                eth2
    loopbacks: 2001:db8::1/128 (o1)            2001:db8::2/128 (o2)
    Router-IDs: o1 starts 1.1.1.1, o2 fixed 2.2.2.2
  ```

  Scenario: Setup point-to-point topology and reach Full
    Given a clean test environment
    When I create namespace "o1"
    And I create namespace "o2"
    And I connect namespace "o1" interface "eth1" to namespace "o2" interface "eth2"
    And I start zebra-rs in namespace "o1"
    And I start zebra-rs in namespace "o2"
    And I apply config "o1.yaml" to namespace "o1"
    And I apply config "o2.yaml" to namespace "o2"
    And I wait 30 seconds

    Then show command "show ospfv3 neighbor" in namespace "o1" should contain "Full"
    And show command "show ospfv3 neighbor" in namespace "o1" should contain "2.2.2.2"
    And show command "show ospfv3 neighbor" in namespace "o2" should contain "Full"
    And show command "show ospfv3 neighbor" in namespace "o2" should contain "1.1.1.1"
    And show command "show ospfv3 database" in namespace "o2" should contain "1.1.1.1"

  Scenario: Changing o1's Router-ID re-forms the adjacency and withdraws the old identity
    Given the test topology exists
    When I apply command "set router ospfv3 router-id 9.9.9.9" in namespace "o1"
    # New neighbour forms under the new Router-ID; the old neighbour ages
    # out on its dead timer (~40s), so poll generously.
    And I wait 15 seconds
    Then show command "show ospfv3 neighbor" in namespace "o2" should eventually contain "9.9.9.9"
    And show command "show ospfv3 neighbor" in namespace "o2" should eventually contain "Full"
    # The old Router-ID disappears from the neighbour table (dead timer) and
    # from the database (its self-originated LSAs were flushed, not left to
    # age out for ~1 h).
    And show command "show ospfv3 neighbor" in namespace "o2" should eventually not contain "1.1.1.1"
    And show command "show ospfv3 database" in namespace "o2" should eventually not contain "1.1.1.1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "o1"
    And I stop zebra-rs in namespace "o2"
    And I delete namespace "o1"
    And I delete namespace "o2"
    Then the test environment should be clean
