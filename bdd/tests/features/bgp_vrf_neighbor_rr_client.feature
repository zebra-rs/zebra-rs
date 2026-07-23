@serial
@bgp_vrf_neighbor_rr_client
Feature: Per-VRF BGP neighbor route-reflector client
  As an operator running iBGP CE peers inside a VRF
  I want `router bgp vrf <name> neighbor <addr> route-reflector client` to
  reflect iBGP-learned routes to that CE
  So that route reflection works on a per-VRF CE session exactly as on a
  global neighbor — an iBGP-learned route reaches a client but not a
  plain iBGP peer.

  All three CEs are iBGP (AS 65000, same as PE1). CE1 originates
  10.0.1.1/32. iBGP-learned routes are not re-advertised to another iBGP
  peer unless that peer is a route-reflector client:
   * CE2 — route-reflector client → receives 10.0.1.1/32
   * CE3 — plain iBGP (control)    → does NOT receive it

  Test Topology (4 namespaces, all CE links in vrf-cust):
  ```
   ce1(65000) ─┐
   ce2(65000) ─┼─ pe1 (65000, vrf-cust, route reflector)
   ce3(65000) ─┘
  ```

  Scenario: Build the route-reflector VRF topology
    Given a clean test environment
    When I create namespace "ce1"
    And I create namespace "pe1"
    And I create namespace "ce2"
    And I create namespace "ce3"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I connect namespace "pe1" interface "ce2" to namespace "ce2" interface "pe1"
    And I connect namespace "pe1" interface "ce3" to namespace "ce3" interface "pe1"
    And I start zebra-rs in namespace "ce1"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "ce2"
    And I start zebra-rs in namespace "ce3"
    And I apply config "ce1.yaml" to namespace "ce1"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "ce2.yaml" to namespace "ce2"
    And I apply config "ce3.yaml" to namespace "ce3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "ce1" to "10.1.0.1" should eventually be "Established"
    And BGP session in "ce2" to "10.2.0.1" should eventually be "Established"
    And BGP session in "ce3" to "10.3.0.1" should eventually be "Established"

  Scenario: A route-reflector client receives the reflected iBGP route
    Given the test topology exists
    Then show command "show bgp 10.0.1.1/32" in namespace "ce2" should eventually contain "10.0.1.1/32"

  Scenario: A plain iBGP peer does not receive the reflected route
    # Control: without route-reflector client, PE1 does not re-advertise an
    # iBGP-learned route to another iBGP peer.
    Given the test topology exists
    Then show command "show bgp 10.0.1.1/32" in namespace "ce3" should not contain "10.0.1.1/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "ce2"
    And I stop zebra-rs in namespace "ce3"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    And I delete namespace "ce2"
    And I delete namespace "ce3"
    Then the test environment should be clean
