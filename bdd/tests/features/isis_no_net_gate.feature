@isis_no_net_gate
@isis
Feature: IS-IS no-NET hello gate (no identity, no wire)
  As a network operator
  I want an IS-IS instance without a configured NET to stay silent on
  the wire — an enabled circuit must not emit Hellos under the default
  all-zero system-id (0000.0000.0000), which peers would key a phantom
  neighbor under — and to come up promptly once the NET is configured.

  Test Topology:
  ```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
       2001:db8:1::1/64   2001:db8:1::2/64
            (vz1ns)             (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          └─────────┘     └─────────┘
   lo: 2001:db8:0:ffff::1   lo: 2001:db8:0:ffff::2
              /128                  /128
  ```

  Config files:
  - z1-1.yaml: IS-IS L2 with IPv6 on lo + vz1ns, but NO net configured.
  - z2-1.yaml: full IS-IS L2 config with net 49.0001.0000.0000.0002.00.

  Scenario: Setup topology with z1 enabled but identity-less
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with loopback and veth interface on the bridge "br0"
    And I create namespace "z2" with loopback and veth interface on the bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 10 seconds
    Then ping from "z1" to "2001:db8:1::2" should succeed
    And ping from "z2" to "2001:db8:1::1" should succeed

  Scenario: An identity-less z1 sends no Hellos, so z2 learns no neighbor
    Given the test topology exists
    # Without the gate, z1's enable-instant and periodic Hellos carry
    # source-id 0000.0000.0000, z2 keys a phantom neighbor under it and
    # the 3-way handshake completes — the control run on the pre-fix
    # binary showed the impostor reaching Up (displayed under z1's
    # hostname once its zero-keyed LSP delivers the hostname TLV).
    Then show command "show isis neighbor" in namespace "z2" should not contain "0000.0000.0000"
    And show command "show isis neighbor" in namespace "z2" should not contain "z1"
    And show command "show isis neighbor" in namespace "z2" should not contain "Up"
    And show command "show isis neighbor" in namespace "z2" should not contain "Init"

  Scenario: Configuring the NET brings the adjacency up promptly
    Given the test topology exists
    When I apply command "set router isis net 49.0001.0000.0000.0001.00" in namespace "z1"
    Then show command "show isis neighbor" in namespace "z2" should eventually contain "Up"
    And show command "show isis neighbor" in namespace "z1" should eventually contain "Up"
    And show command "show isis neighbor" in namespace "z2" should not contain "0000.0000.0000"
    And ping from "z1" to "2001:db8:0:ffff::2" should eventually succeed
    And ping from "z2" to "2001:db8:0:ffff::1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
