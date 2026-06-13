@serial
@bgp_evpn_capability
Feature: BGP L2VPN/EVPN capability negotiation
  As a network operator
  I want two zebra-rs instances to negotiate the L2VPN/EVPN multiprotocol
  capability (AFI=25 / SAFI=70) and bring an iBGP session to Established,
  so that the foundation for EVPN Type-2 / Type-3 advertisements is
  validated end-to-end before route exchange is implemented.

  No EVPN routes flow in this scenario — capability negotiation is the
  unit under test. Route exchange (Type-2 MAC/IP, Type-3 Inclusive
  Multicast) lands in follow-up features.

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

  Both peers enable two AFI/SAFIs:
    - ipv4 (so the session has a fallback AF and matches the
      established BDD pattern)
    - evpn  (the AF this scenario is actually validating)

  Config files:
  - z1-1.yaml: AS 65001, peer to 192.168.0.2, evpn enabled
  - z2-1.yaml: AS 65001, peer to 192.168.0.1, evpn enabled

  Scenario: Setup topology and establish iBGP session with EVPN capability
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

  Scenario: L2VPN/EVPN capability is advertised and received on both sides
    Given the test topology exists
    Then show command "show bgp neighbors 192.168.0.2" in namespace "z1" should contain "L2VPN EVPN: advertised and received"
    And show command "show bgp neighbors 192.168.0.1" in namespace "z2" should contain "L2VPN EVPN: advertised and received"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
