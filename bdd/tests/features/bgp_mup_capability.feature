@serial
@bgp_mup_capability
Feature: BGP Mobile User Plane (MUP) capability negotiation
  As a network operator
  I want two zebra-rs instances to negotiate the BGP MUP multiprotocol
  capability (SAFI 85, RFC 9833) for BOTH IPv4-MUP (AFI 1) and IPv6-MUP
  (AFI 2) from a single `afi-safi mup enabled true` knob, and
  bring an iBGP session to Established, so the foundation for MUP route
  exchange (ISD / DSD / ST1 / ST2) is validated before origination is
  implemented.

  No MUP routes flow in this scenario — capability negotiation is the unit
  under test. zebra-rs cannot originate MUP routes yet (controller phase),
  so route exchange is exercised in a later feature once a peer can emit
  them.

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65001 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
  ```

  Both peers enable two AFI/SAFIs:
    - ipv4 (so the session has a fallback AF and matches the
      established BDD pattern)
    - mup (the single knob this scenario validates; it
      negotiates IPv4-MUP and IPv6-MUP)

  Config files:
  - z1-1.yaml: AS 65001, peer to 192.168.0.2, mup enabled
  - z2-1.yaml: AS 65001, peer to 192.168.0.1, mup enabled

  Scenario: Setup topology and establish iBGP session with MUP capability
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: IPv4 and IPv6 MUP capabilities are advertised and received on both sides
    Given the test topology exists
    Then show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "IPv4 MUP: advertised and received"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "IPv6 MUP: advertised and received"
    And show command "show bgp neighbor 192.168.0.1" in namespace "z2" should contain "IPv4 MUP: advertised and received"
    And show command "show bgp neighbor 192.168.0.1" in namespace "z2" should contain "IPv6 MUP: advertised and received"

  Scenario: show bgp mup renders the (empty) MUP RIB header
    Given the test topology exists
    Then show command "show bgp mup" in namespace "z1" should contain "Network (MUP NLRI)"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
