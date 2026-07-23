@serial
@bgp_vrf_neighbor_show
Feature: Per-VRF BGP neighbor config-echo in the neighbor detail show
  As an operator of an L3VPN PE
  I want the per-VRF neighbor session and per-AFI knobs to be reflected in
  `show bgp vrf <name> neighbor`
  So that description, timers, update-source, ebgp-multihop, ttl-security,
  add-path, and graceful-restart / long-lived-GR are staged and rendered
  for a per-VRF CE neighbor exactly as for a global neighbor.

  One scenario per knob, each asserting the neighbor detail renders the
  configured value. CE1 carries the session + per-AFI knobs (established so
  the negotiated capabilities show); CE2 carries ttl-security, which is
  mutually exclusive with CE1's ebgp-multihop (echoed regardless of session
  state).

  Test Topology (3 namespaces, CE links in vrf-cust):
  ```
   ce1(65001) ─┐
               ├─ pe1 (65000, vrf-cust)
   ce2(65002) ─┘
  ```

  Scenario: Build the config-echo VRF topology
    Given a clean test environment
    When I create namespace "ce1"
    And I create namespace "pe1"
    And I create namespace "ce2"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I connect namespace "pe1" interface "ce2" to namespace "ce2" interface "pe1"
    And I start zebra-rs in namespace "ce1"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "ce2"
    And I apply config "ce1.yaml" to namespace "ce1"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "ce2.yaml" to namespace "ce2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "ce1" to "10.1.0.1" should eventually be "Established"

  Scenario: description is rendered
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust neighbor" in namespace "pe1" should eventually contain "Description: ce1-peer-note"

  Scenario: hold-time is rendered
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust neighbor" in namespace "pe1" should eventually contain "Hold time 90 seconds"

  Scenario: idle-hold-time is rendered
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust neighbor" in namespace "pe1" should eventually contain "Next idle hold timer value 4 seconds"

  Scenario: update-source is rendered as the local host
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust neighbor" in namespace "pe1" should eventually contain "Local host: 10.1.0.1"

  Scenario: ebgp-multihop is rendered
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust neighbor" in namespace "pe1" should eventually contain "up to 5 hops away"

  Scenario: add-path capability is rendered
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust neighbor" in namespace "pe1" should eventually contain "Add Path:"

  Scenario: graceful-restart is negotiated with a restart time
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust neighbor" in namespace "pe1" should eventually contain "Graceful Restart:"
    And show command "show bgp vrf vrf-cust neighbor" in namespace "pe1" should eventually contain "advertised(restart time:"

  Scenario: long-lived-graceful-restart is rendered
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust neighbor" in namespace "pe1" should eventually contain "Long-Lived Graceful Restart:"

  Scenario: ttl-security (GTSM) is rendered
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust neighbor" in namespace "pe1" should eventually contain "TTL security (GTSM) enabled"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "ce2"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    And I delete namespace "ce2"
    Then the test environment should be clean
