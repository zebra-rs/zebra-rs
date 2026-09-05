@serial
@bgp_lu_dynamic_transit_review
Feature: Dynamic LU next-hop-self peers activate transit labels
  The reflector learns c1's route before c2 connects. Accepting c2 through
  a listen-range must reconcile the inherited next-hop-self requirement
  immediately, including labels for routes already in the Loc-RIB.

  Scenario: Setup topology and establish the labeled-unicast sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "rr" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "c1" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "c2" with IP "192.168.0.3/24" on bridge "br0"
    And I create dummy interface "lo1" with address "10.1.0.1/32" in namespace "c1"
    And I create dummy interface "lo1" with address "10.2.0.1/32" in namespace "c2"
    And I start zebra-rs in namespace "rr"
    And I start zebra-rs in namespace "c1"
    And I start zebra-rs in namespace "c2"
    And I apply config "rr.yaml" to namespace "rr"
    And I apply config "c1.yaml" to namespace "c1"
    And I wait 5 seconds for BGP to operate
    And I apply config "c2.yaml" to namespace "c2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "rr" to "192.168.0.2" should be "Established"
    And BGP session in "rr" to "192.168.0.3" should be "Established"

  Scenario: Dynamic next-hop-self iBGP arrival must enable transit labels
    Given the test topology exists
    Then show command "show bgp labeled-unicast" in namespace "c2" should eventually contain "10.1.0.1/32"
    And mpls ilm in namespace "rr" should not be empty

  Scenario: Toggling inherited next-hop-self activates the missing labels
    Given the test topology exists
    When I apply command "set router bgp neighbor-group LU afi-safi label-v4 next-hop-self false" in namespace "rr"
    And I apply command "set router bgp neighbor-group LU afi-safi label-v4 next-hop-self true" in namespace "rr"
    And I wait 5 seconds for BGP to operate
    Then mpls ilm in namespace "rr" should not be empty

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "rr"
    And I stop zebra-rs in namespace "c1"
    And I stop zebra-rs in namespace "c2"
    And I delete namespace "rr"
    And I delete namespace "c1"
    And I delete namespace "c2"
    And I delete bridge "br0"
    Then the test environment should be clean
