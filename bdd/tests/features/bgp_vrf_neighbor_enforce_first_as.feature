@serial
@bgp_vrf_neighbor_enforce_first_as
Feature: Per-VRF BGP neighbor enforce-first-as
  As an operator of an L3VPN PE
  I want `router bgp vrf <name> neighbor <addr> enforce-first-as` to drop a
  CE UPDATE whose left-most AS is not the CE's own AS
  So that the RFC 4271 first-AS check runs on the per-VRF CE receive path,
  exactly as on a global eBGP neighbor — not silently skipped.

  CE1 advertises two routes over one eBGP session:
   * 10.0.1.1/32 — an outbound route-map prepends a FOREIGN AS (65099), so
     it arrives as "65099 65001"; the left-most AS (65099) is not CE1's
     remote-as (65001), so enforce-first-as must drop it.
   * 10.0.1.2/32 — advertised normally ("65001"), left-most AS matches, so
     it is accepted. The control that proves enforce-first-as isn't just
     dropping everything.

  Test Topology (2 namespaces):
  ```
   ce1 (65001) ── pe1 (65000, vrf-cust)
  ```

  Scenario: Build the enforce-first-as VRF topology
    Given a clean test environment
    When I create namespace "ce1"
    And I create namespace "pe1"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I start zebra-rs in namespace "ce1"
    And I start zebra-rs in namespace "pe1"
    And I apply config "ce1.yaml" to namespace "ce1"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "ce1" to "10.1.0.1" should eventually be "Established"

  Scenario: A valid first-AS route is accepted
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust" in namespace "pe1" should eventually contain "10.0.1.2/32"

  Scenario: enforce-first-as drops the foreign-first-AS route
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust" in namespace "pe1" should not contain "10.0.1.1/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    Then the test environment should be clean
