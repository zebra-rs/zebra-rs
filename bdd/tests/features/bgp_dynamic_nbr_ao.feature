@serial
@bgp_dynamic_nbr_ao
Feature: A dynamic (listen-range) peer authenticates with TCP-AO (RFC 5925)
  As a network operator
  I want the tcp-ao key-chain on a listen-range's neighbor-group to protect the range
  So unconfigured sources cannot open a session just by being in the prefix.

  Test Topology:
  ```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐
   │   z2    │ i1────────────i1 │   z1    │
   │ AS65002 │                  │ AS65001 │
   │ .0.2    │                  │ .0.1    │
   └─────────┘                  └─────────┘
  ```

  Requires Linux kernel >= 6.7 on both peers.

  The DUT (z1) has no static neighbors: z2 arrives through the
  listen-range and inherits SENDERS, which carries the tcp-ao
  key-chain. Like the MD5 case, the MKT must be scoped to the whole
  prefix — the peer is materialized only after its SYN is accepted,
  while the kernel verifies the AO MAC during the handshake.

  Config files:
  - z1.yaml:        DUT — SENDERS carries `tcp-ao key-chain BGP-AO`, listen-range 192.168.0.0/24
  - z1-noao.yaml:   same DUT with the group's tcp-ao removed
  - z1-rotated.yaml: DUT whose BGP-AO chain holds a rotated key-string (same IDs)
  - z2.yaml:        client, matching key-chain
  - z2-wrong.yaml:  client, mismatched key-string

  Scenario: Establish a TCP-AO authenticated dynamic session
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z2" interface "i1" to namespace "z1" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP route in "z1" has "10.0.2.2/32"
    And BGP route in "z2" has "10.0.1.1/32"

  Scenario: A mismatched key-string never materializes a peer
    Given the test topology exists
    # The kernel drops the SYN before accept(), so there is no session
    # to reject — and no peer entry on the DUT at all.
    When I apply config "z2-wrong.yaml" to namespace "z2"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should not be "Established"
    And show command "show bgp summary" in namespace "z1" should not contain "192.168.0.2"
    And BGP route in "z1" does not have "10.0.2.2/32"

  Scenario: Restoring the matching key-string re-establishes the session
    Given the test topology exists
    When I apply config "z2.yaml" to namespace "z2"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP route in "z1" has "10.0.2.2/32"

  Scenario: Rotating the key-string on the DUT re-keys the prefix MKT
    Given the test topology exists
    # Same chain name and the same send-id/recv-id, new key-string. The
    # kernel identifies an MKT by (address, prefixlen, send-id, recv-id)
    # and refuses a duplicate with EEXIST, so the reconciler must delete
    # the old MKT before adding the rotated one. If it did not, the
    # listener would keep serving the old key and the now-mismatched
    # client would still get in.
    When I apply config "z1-rotated.yaml" to namespace "z1"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should not be "Established"
    And show command "show bgp summary" in namespace "z1" should not contain "192.168.0.2"

  Scenario: Clearing the group tcp-ao retracts the prefix MKT
    Given the test topology exists
    # With the DUT no longer expecting AO and the client still signing,
    # the handshake cannot complete — proving the MKT was really removed
    # from the listener rather than lingering.
    When I apply config "z1-noao.yaml" to namespace "z1"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should not be "Established"
    And show command "show bgp summary" in namespace "z1" should not contain "192.168.0.2"

  Scenario: Restoring the group tcp-ao re-installs the prefix MKT
    Given the test topology exists
    When I apply config "z1.yaml" to namespace "z1"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP route in "z1" has "10.0.2.2/32"

  # Pure P2P topology (no bridge): deleting each namespace destroys the
  # veth pair ends it holds, so only daemons and namespaces need teardown.
  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
