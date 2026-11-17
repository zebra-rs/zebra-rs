@serial
@bgp_vrf_update_source_interface
Feature: BGP update-source by interface name on a per-VRF neighbor
  As an operator of an L3VPN PE
  I want `update-source <interface>` on a per-VRF neighbor to source the
  session to the CE from that interface's address, the interface being
  one of the neighbor's VRF, so that a CE-facing session follows an
  interface as a default-VRF session does.

  Test Topology (CE links in vrf-cust on pe1):
  ```
   ce1 (65001) ── ce1 ─┐
                       ├─ pe1 (65000, vrf-cust)
   ce2 (no router) ─ ce2 ─┘
  ```

  PE1's neighbor is CE1, 10.1.0.2 on interface `ce1`, with
  `update-source ce2`: the session is to be sourced from the address of
  `ce2`, a second interface of the same VRF (10.2.0.1 once the scenario
  sets it). The kernel would pick 10.1.0.1, of `ce1`. CE1 is the
  observer: it never dials, and has a passive neighbor for each of the
  two addresses. So which of CE1's sessions comes up says which address
  PE1 sourced the session from.

  The session is asserted from CE1, where the neighbor is a default-VRF
  one: the `BGP session` step does not see a per-VRF neighbor.

  Scenario: A per-VRF neighbor is not dialed while the interface has no address
    Given a clean test environment
    When I create namespace "ce1"
    And I create namespace "pe1"
    And I create namespace "ce2"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I connect namespace "pe1" interface "ce2" to namespace "ce2" interface "pe1"
    And I start zebra-rs in namespace "ce1"
    And I start zebra-rs in namespace "pe1"
    And I apply config "ce1.yaml" to namespace "ce1"
    And I apply config "pe1.yaml" to namespace "pe1"
    # Longer than PE1's idle hold (3 s) by a margin: a PE1 that dialed
    # at all would be up with CE1's 10.1.0.1 neighbor by now.
    And I wait 15 seconds for BGP to operate
    Then show command "show bgp vrf vrf-cust neighbor" in namespace "pe1" should contain "Update source is ce2 (no usable IPv4 address; neighbor is not dialed)"
    And BGP session in "ce1" to "10.1.0.1" should not be "Established"
    And BGP session in "ce1" to "10.2.0.1" should not be "Established"

  Scenario: It is dialed from the address of the VRF interface when one comes
    Given the test topology exists
    When I apply command "set interface ce2 ipv4 address 10.2.0.1/30" in namespace "pe1"
    Then BGP session in "ce1" to "10.2.0.1" should eventually be "Established"
    And show command "show bgp vrf vrf-cust neighbor" in namespace "pe1" should eventually contain "Update source is ce2 (10.2.0.1)"
    And show command "show bgp vrf vrf-cust neighbor" in namespace "pe1" should eventually contain "Local host: 10.2.0.1"
    And BGP session in "ce1" to "10.1.0.1" should not be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    And I delete namespace "ce2"
    Then the test environment should be clean
