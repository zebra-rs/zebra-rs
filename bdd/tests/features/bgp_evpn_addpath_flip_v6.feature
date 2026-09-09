@serial
@bgp_evpn_addpath_flip_v6
Feature: EVPN AddPath members receive every candidate, and a superseded path-id is withdrawn on a flip (IPv6 Type-5)
  As a network operator
  I want an EVPN route reflector with add-path send toward a leaf to send
  the leaf every candidate path of an EVPN key and to withdraw the path-id
  of a candidate that leaves the reflector's table, so the leaf never keeps
  forwarding toward a departed VTEP.

  Test Topology (one bridge, 192.168.0.0/24):
  ```
  ┌─────────────┐          ┌─────────────┐          ┌─────────────┐
  │ z1 (VTEP A) │──iBGP──▶│  z2 (RR)    │◀──iBGP──│ z3 (leaf)   │
  │ RD 65001:100│          │ clients:    │ add-path │ add-path    │
  │ Type-5 2001:db8:1::/64│          │ z1, z4, z3  │  send    │ receive     │
  └─────────────┘          └─────────────┘          └─────────────┘
   192.168.0.1                   ▲ 192.168.0.2       192.168.0.3
  ┌─────────────┐                │
  │ z4 (VTEP B) │──────iBGP──────┘
  │ RD 65001:100│
  │ Type-5 2001:db8:1::/64│
  └─────────────┘
   192.168.0.4
  ```

  z1 and z4 both originate an EVPN Type-5 for 2001:db8:1::/64 under the SAME route
  distinguisher, so the reflector holds two candidates for one EVPN key;
  z1's path wins (lower ORIGINATOR_ID). The reflector negotiates AddPath
  send toward z3. z4 is brought up only after z1's path is on the leaf, so
  z1's path is the best from the start and z4's path is never the best.

  Review finding #7: the reflector's AddPath fan-out iterated the single
  selected best path, so z3 never received z4's path; and when z1's
  session died the survivor was advertised under its own path-id while
  z1's path-id was never withdrawn, so z3 kept selecting and forwarding
  to the dead VTEP.

  Scenario: Setup topology
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.0.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I apply config "z3-1.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z2" to "192.168.0.3" should be "Established"

  Scenario: The reflector reflects VTEP A's path to the AddPath leaf
    Given the test topology exists
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "2001:db8:1::"
    And show command "show bgp evpn" in namespace "z3" should eventually contain "2001:db8:1::"
    And show command "show bgp neighbor 192.168.0.3 advertised-routes evpn" in namespace "z2" should eventually contain "192.168.0.1"

  Scenario: VTEP B comes up and the AddPath leaf receives its path as a second candidate
    Given the test topology exists
    When I apply config "z4-1.yaml" to namespace "z4"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.4" should be "Established"
    # VTEP B's path is not the best (VTEP A has the lower ORIGINATOR_ID); an
    # AddPath member must still receive it under its own path-id. Pre-fix
    # the fan-out sent the selected best only, so it never left the reflector.
    And show command "show bgp neighbor 192.168.0.3 advertised-routes evpn" in namespace "z2" should eventually contain "192.168.0.4"
    And show command "show bgp neighbor 192.168.0.3 advertised-routes evpn" in namespace "z2" should contain "192.168.0.1"
    And show command "show bgp neighbor 192.168.0.2 received-routes evpn" in namespace "z3" should eventually contain "192.168.0.4"

  Scenario: VTEP A dies and its path-id is withdrawn from the leaf
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I wait 5 seconds for BGP to operate
    Then show command "show bgp evpn" in namespace "z2" should eventually not contain "192.168.0.1"
    # The regression assertions: pre-fix the survivor was re-advertised under
    # its own path-id but VTEP A's path-id stayed in the leaf's table (the
    # leaf kept selecting it — lower ORIGINATOR_ID) and in the reflector's
    # Adj-RIB-Out toward the leaf.
    And show command "show bgp evpn" in namespace "z3" should eventually not contain "192.168.0.1"
    And show command "show bgp evpn" in namespace "z3" should contain "192.168.0.4"
    And show command "show bgp neighbor 192.168.0.2 received-routes evpn" in namespace "z3" should eventually not contain "192.168.0.1"
    And show command "show bgp neighbor 192.168.0.3 advertised-routes evpn" in namespace "z2" should eventually not contain "192.168.0.1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "z4"
    And I delete bridge "br0"
    Then the test environment should be clean
