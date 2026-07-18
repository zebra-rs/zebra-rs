@serial
@bgp_evpn_rr_withdraw
Feature: EVPN route reflector propagates a client's withdraw
  As a network operator
  I want an EVPN route reflector to forward a client's withdraw to the
  other clients, so nobody keeps forwarding to a departed host's VTEP.

  Test Topology:
  ```
  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
  │     z1      │ EVPN │     z2      │ EVPN │     z3      │
  │  AS 65001   │◀───▶│  AS 65001   │◀───▶│  AS 65001   │
  │ vrf-blue    │ iBGP │   route     │ iBGP │  (client)   │
  │ RD 65001:100│      │  reflector  │      │             │
  │ Type-5 from │      │  (both are  │      │             │
  │ 10.1.0.0/24 │      │   clients)  │      │             │
  └─────────────┘      └─────────────┘      └─────────────┘
   192.168.0.1          192.168.0.2          192.168.0.3
  ```

  z1 originates an EVPN Type-5 for 10.1.0.0/24 (`evpn advertise-ipv4`);
  z2 reflects it to z3. Review finding #5: a received EVPN withdraw
  removed the route from the reflector's Loc-RIB but was never fanned
  to other peers — z3 kept the stale route (and its VTEP forwarding
  state) until its session bounced.

  Scenario: Setup topology
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I apply config "z3-1.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z2" to "192.168.0.3" should be "Established"

  Scenario: The reflector reflects z1's Type-5 to z3
    Given the test topology exists
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "10.1.0.0"
    And show command "show bgp evpn" in namespace "z3" should eventually contain "10.1.0.0"

  Scenario: z1's withdraw reaches z3 through the reflector
    Given the test topology exists
    When I apply config "z1-2.yaml" to namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then show command "show bgp evpn" in namespace "z2" should eventually not contain "10.1.0.0"
    # The regression assertion: pre-fix the reflector removed the route
    # locally but never sent MP_UNREACH onward, so z3 held it forever.
    And show command "show bgp evpn" in namespace "z3" should eventually not contain "10.1.0.0"

  Scenario: Re-advertising the network reaches z3 again
    Given the test topology exists
    When I apply config "z1-1.yaml" to namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then show command "show bgp evpn" in namespace "z3" should eventually contain "10.1.0.0"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
