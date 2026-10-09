@bgp_mup_c_bind_retry
Feature: The MUP controller binds its PFCP listener once its address appears
  As a network operator
  I want the BGP MUP Controller (MUP-C) to keep trying to bind its PFCP
  listen address while the address is on no interface (the config applied
  before the interface's address at boot, say)
  So that MUP-C comes up as soon as the address does, without a config
  change

  Test Topology:
  ```
  ┌───────────────┐
  │      br0      │
  └───────┬───────┘
          │
     ┌────┴─────┐
     │    z1    │  MUP-C, PFCP listen-address 192.168.0.1:8805
     │ 192.168. │  vz1ns starts with 192.168.0.11/24 only
     │ 0.11/24  │
     └────┬─────┘
          │ PFCP/N4 (UDP 8805)
     ┌────┴──────┐
     │pfcp-inject│  (SMF simulator, run in z1)
     └───────────┘
  ```

  Before, a failed bind was final: the listener stayed down until the listen
  address or port changed in the config.

  NOTE: `pfcp-inject` must be on the BDD host PATH, as for
  `bgp_mup_st2_base`.

  Scenario: Setup with the listen address on no interface
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.11/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"
    Then show command "show bgp mup-c" in namespace "z1" should eventually contain "Admin state : enabled"
    And show command "show bgp mup-c" in namespace "z1" should contain "PFCP listen : down"

  Scenario: The listener binds once the address is added
    Given the test topology exists
    When I execute "ip addr add 192.168.0.1/24 dev vz1ns" in namespace "z1"
    Then show command "show bgp mup-c" in namespace "z1" should eventually contain "PFCP listen : 192.168.0.1:8805"
    # It serves PFCP: the SMF's association and session reach MUP-C, and the
    # session originates its ST2.
    When I execute "pfcp-inject --target 192.168.0.1 --port 8805 --ue-ipv4 192.0.2.5 --teid 0x12345678 --endpoint 10.0.0.1 --core-endpoint 10.0.0.1 --core-teid 0x12345678 --network-instance core" in namespace "z1"
    Then show command "show bgp mup-c" in namespace "z1" should eventually contain "Associations: 1"
    And show command "show bgp mup-c session" in namespace "z1" should eventually contain "192.0.2.5"
    And show command "show bgp mup" in namespace "z1" should eventually contain "[ST2][65000:100][ep=10.0.0.1][teid=305419896]"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete bridge "br0"
    Then the test environment should be clean
