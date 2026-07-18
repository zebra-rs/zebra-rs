@serial
@bgp_out_policy_delete
Feature: Deleting an outbound route-policy re-advertises the suppressed routes
  As a network operator
  I want removing a neighbor's `afi-safi ipv4 policy out` binding to
  re-advertise the routes that policy was suppressing.

  Test Topology:
  ```
  z1 (AS65001) ──eBGP── z2 (AS65002)
  192.168.0.1/24        192.168.0.2/24
  ```
  z1 originates 10.0.0.1/32 and 10.0.0.2/32. With `policy out DENY-ALL`
  bound toward z2, neither reaches z2. Review finding #12: deleting that
  binding left z1's cached out-policy snapshot still denying everything
  and never re-advertised — z2 stayed route-less until a new policy name
  was bound.

  Config files:
  - z1-deny.yaml: z1 with `afi-safi ipv4 policy out DENY-ALL`.
  - z1-nopolicy.yaml: same, minus the policy binding (the delete diff).
  - z2.yaml: plain AS65002 peer.

  Scenario: Setup; the out-policy denies both routes to z2
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-deny.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP route in "z2" does not have "10.0.0.1/32"
    And BGP route in "z2" does not have "10.0.0.2/32"

  Scenario: Deleting the out-policy re-advertises both routes
    Given the test topology exists
    When I apply config "z1-nopolicy.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    # The regression assertion: pre-fix z1's cached snapshot kept
    # denying, so z2 never saw these; with the fix the unbind pushes a
    # clearing resolve and soft-out re-advertises.
    Then BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z2" has "10.0.0.2/32"

  Scenario: Re-binding the out-policy denies them again
    Given the test topology exists
    When I apply config "z1-deny.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then BGP route in "z2" does not have "10.0.0.1/32"
    And BGP route in "z2" does not have "10.0.0.2/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
