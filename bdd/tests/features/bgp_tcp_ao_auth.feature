@serial
@bgp_tcp_ao_auth
Feature: BGP TCP Authentication Option (RFC 5925 / RFC 5926)
  As a network operator
  I want to protect a BGP session with TCP-AO using an RFC 8177 key
  chain and verify that matching MKTs on both peers establish the
  session.

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
  ```

  Requires Linux kernel >= 6.7 on both peers.

  Config files:
  - z1-1.yaml: AS 65001, tcp-ao key-chain BGP-AO (hmac-sha-1,
    send-id=100, recv-id=100, key "shared-ao-secret").
  - z2-1.yaml: AS 65002, mirror configuration.

  Scenario: Establish a TCP-AO authenticated BGP session
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

  Scenario: Switching to a mismatched key-chain drops the session
    Given the test topology exists
    # z2 swaps its tcp-ao key-chain reference (BGP-AO -> BGP-AO-WRONG,
    # a different key-string). The MKT is installed on the listener at
    # accept time, so the key change only resets the session because the
    # key-chain callback now bounces it — otherwise the old session
    # would survive under the old key until the hold timer expired.
    When I apply config "z2-2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.0.2" should eventually not be "Established"
    And BGP session in "z2" to "192.168.0.1" should eventually not be "Established"

  Scenario: Restoring the matching key-chain re-establishes the session
    Given the test topology exists
    When I apply config "z2-1.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Established"
    And BGP session in "z2" to "192.168.0.1" should eventually be "Established"

  Scenario: Rotating the key-string within the same chain drops the session
    Given the test topology exists
    # z2 keeps its neighbor pointed at the SAME chain name (BGP-AO) and
    # the SAME send-id/recv-id, but rotates the key-string
    # (shared-ao-secret -> rotated-ao-secret). This edits the chain
    # content, so it arrives via the policy key-chain callback rather
    # than the neighbor tcp-ao callback. apply_ao_refresh_all re-installs
    # the new MKT on the listener under the unchanged (addr, send-id,
    # recv-id) tuple, so the established session would survive on the old
    # key until the hold timer expired — unless the resolved-key delta
    # bounces it.
    When I apply config "z2-3.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.0.2" should eventually not be "Established"
    And BGP session in "z2" to "192.168.0.1" should eventually not be "Established"

  Scenario: Restoring the original key-string re-establishes the session
    Given the test topology exists
    When I apply config "z2-1.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Established"
    And BGP session in "z2" to "192.168.0.1" should eventually be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
