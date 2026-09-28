@serial
@bgp_vrf_rt_change_v6
Feature: A route-target change takes effect on the routes already held (IPv6)
  As a network operator
  I want a VRF's route-target import and export changes to apply to the
  VPN routes already in the table
  So a VRF imports exactly what its current route-targets select, without
  waiting for the routes to be re-sent.

  Import route-targets were read only when a route arrived: adding one
  imported none of the matching routes already held, and removing one
  left the routes it had imported. An export route-target change re-tagged
  the VRF's routes for the peers but never re-ran the import, so a sibling
  VRF on the same PE kept a route it no longer imports, and one that now
  imports it did not get it. The twin is `bgp_vrf_rt_change`.

  Test Topology (one namespace; the VRFs leak locally):
  ```
  pe1 (AS 65000)
    red   RD 65000:1  exports 2001:db8:24:1::/64 with RT 65000:200
    gold  RD 65000:3  exports 2001:db8:24:9::/64 with RT 65000:100
    blue  RD 65000:2  imports 65000:100
    green RD 65000:4  imports 65000:300
  ```

  Config files:
  - pe1.yaml: the four VRFs and their `network` statements.

  Scenario: Setup; blue imports gold's route and not red's
    Given a clean test environment
    When I create namespace "pe1"
    And I start zebra-rs in namespace "pe1"
    And I apply config "pe1.yaml" to namespace "pe1"
    # Control: local leaking by route-target works.
    Then show command "show bgp vrf blue ipv6" in namespace "pe1" should eventually contain "2001:db8:24:9::/64"
    And show command "show bgp vrf blue ipv6" in namespace "pe1" should not contain "2001:db8:24:1::/64"

  Scenario: Adding an import route-target imports the matching held route
    Given the test topology exists
    When I apply command "set vrf blue ipv6 route-target import 65000:200" in namespace "pe1"
    # Pre-fix red's route was never imported: nothing re-read the table.
    Then show command "show bgp vrf blue ipv6" in namespace "pe1" should eventually contain "2001:db8:24:1::/64"

  Scenario: Removing the import route-target withdraws what it imported
    Given the test topology exists
    When I apply command "delete vrf blue ipv6 route-target import 65000:200" in namespace "pe1"
    Then show command "show bgp vrf blue ipv6" in namespace "pe1" should eventually not contain "2001:db8:24:1::/64"
    And show command "show bgp vrf blue ipv6" in namespace "pe1" should contain "2001:db8:24:9::/64"

  Scenario: Changing an export route-target moves the route between sibling VRFs
    Given the test topology exists
    When I apply command "delete vrf gold ipv6 route-target export 65000:100" in namespace "pe1"
    And I apply command "set vrf gold ipv6 route-target export 65000:300" in namespace "pe1"
    # Pre-fix blue kept gold's route and green never got it.
    Then show command "show bgp vrf green ipv6" in namespace "pe1" should eventually contain "2001:db8:24:9::/64"
    And show command "show bgp vrf blue ipv6" in namespace "pe1" should eventually not contain "2001:db8:24:9::/64"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "pe1"
    And I delete namespace "pe1"
    Then the test environment should be clean
