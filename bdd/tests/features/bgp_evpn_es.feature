@serial
@bgp_evpn_es
Feature: BGP EVPN Ethernet Segment discovery (RFC 7432 Type-4)
  As a network operator
  I want each PE attached to a multihomed Ethernet Segment to advertise a
  Type-4 Ethernet Segment route (carrying the auto-derived ES-Import RT and a
  DF Election EC) and to discover the other PEs on the same ES, so the
  control-plane foundation for DF election and all-active multihoming is in
  place. (DF election itself and the data plane are later phases.)

  Test Topology — two iBGP (AS 65001) EVPN speakers on a shared transport
  bridge br0, both configured with the SAME Ethernet Segment es1 / ESI (the
  defining property of an ES — the shared CE looks identical to both PEs):
  ```
  ┌─────────────────────────────────┐
  │               br0               │
  └───────┬─────────────────┬───────┘
     ┌────┴────┐       ┌────┴────┐
     │   z1    │       │   z2    │   both: ethernet-segment es1
     │ .0.1/24 │       │ .0.2/24 │   esi 00:11:..:99
     └─────────┘       └─────────┘
  ```

  Scenario: Setup topology and EVPN iBGP with a shared Ethernet Segment
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"

  Scenario: Each PE originates a Type-4 ES route the other imports
    Given the test topology exists
    # z1 sees z2's Type-4 in the EVPN RIB: [4]:[ESI]:[IPlen]:[OrigIP=z2].
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "[4]:[00:11:22:33:44:55:66:77:88:99]:[32]:[192.168.0.2]"
    # The Type-4 carries the auto-derived ES-Import RT (from ESI octets 1..7).
    And show command "show bgp evpn" in namespace "z1" should eventually contain "es-import:11:22:33:44:55:66"
    # ... and a default-algorithm DF Election EC (RFC 8584).
    And show command "show bgp evpn" in namespace "z1" should eventually contain "df-election:alg0"
    # z2 symmetrically sees z1's Type-4.
    And show command "show bgp evpn" in namespace "z2" should eventually contain "[4]:[00:11:22:33:44:55:66:77:88:99]:[32]:[192.168.0.1]"

  Scenario: ES membership shows both PEs on z1
    Given the test topology exists
    # z1's ethernet-segment view lists both VTEPs (its own + z2's), keyed by
    # the shared ESI, with the local one tagged.
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "ESI: 00:11:22:33:44:55:66:77:88:99"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "Member VTEPs (2)"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should contain "192.168.0.1 (local)"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should contain "192.168.0.2"

  Scenario: Removing the ES on z2 withdraws its Type-4 from z1
    Given the test topology exists
    When I apply config "z2-noes.yaml" to namespace "z2"
    Then show command "show bgp evpn" in namespace "z1" should eventually not contain "[4]:[00:11:22:33:44:55:66:77:88:99]:[32]:[192.168.0.2]"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "Member VTEPs (1)"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
