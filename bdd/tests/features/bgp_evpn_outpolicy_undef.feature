@serial
@bgp_evpn_outpolicy_undef
Feature: EVPN outbound policy rebound to an undefined name is deny-all
  As a network operator
  I want a BGP neighbor whose EVPN outbound policy is rebound to a
  policy name that does not exist to immediately withdraw the routes it
  was advertising, rather than keep leaking them with the previously
  resolved policy still applied.

  A bound-but-unresolved peer policy is deny-all. Previously the policy
  actor stayed silent when a peer registered an undefined policy name, so
  no soft-reconfiguration fired and the stale resolved policy lingered:
  the neighbor kept advertising. The actor now answers even with a `None`
  policy, which clears the stale resolve and drives a soft-out that
  withdraws the now-denied routes — all without a session reset.

  The exercise: z1 originates 10.1.0.0/24 in vrf-blue and advertises it to
  z2 as an EVPN Type-5 route. z1's EVPN outbound policy starts bound to an
  existing PERMIT-ALL policy (z2 sees the route), is then rebound to the
  undefined NOPE (z2 must lose the route), and finally NOPE is defined as
  permit (z2 must see the route again).

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65001 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
  ```

  Config files:
  - z1-permit.yaml: vrf-blue originates 10.1.0.0/24, EVPN out-policy bound
    to the existing PERMIT-ALL.
  - z1-undef.yaml: EVPN out-policy rebound to the undefined NOPE.
  - z1-recover.yaml: NOPE defined as a permit policy.
  - z2-1.yaml: EVPN receiver importing RT 65001:100 into vrf-blue.

  Scenario: Setup topology and verify the route is advertised under PERMIT-ALL
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-permit.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And show command "show bgp evpn" in namespace "z2" should contain "10.1.0.0"

  Scenario: Rebinding the EVPN out-policy to an undefined name withdraws the route
    Given the test topology exists
    When I apply config "z1-undef.yaml" to namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And show command "show bgp evpn" in namespace "z2" should not contain "10.1.0.0"

  Scenario: Defining the previously-undefined policy re-advertises the route
    Given the test topology exists
    When I apply config "z1-recover.yaml" to namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And show command "show bgp evpn" in namespace "z2" should contain "10.1.0.0"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
