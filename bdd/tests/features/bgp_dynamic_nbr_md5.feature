@serial
@bgp_dynamic_nbr_md5
Feature: A dynamic (listen-range) peer authenticates with TCP MD5 (RFC 2385)
  As a network operator
  I want the password on a listen-range's neighbor-group to protect the range
  So unconfigured sources cannot open a session just by being in the prefix.

  Test Topology:
  ```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐
   │   z2    │ i1────────────i1 │   z1    │
   │ AS65002 │                  │ AS65001 │
   │ .0.2    │                  │ .0.1    │
   └─────────┘                  └─────────┘
  ```

  The DUT (z1) has no static neighbors: z2 arrives through the
  listen-range and inherits SENDERS, which carries the password.

  This needs a listener key scoped to the whole *prefix*, not to a peer
  address: a dynamic peer does not exist until its SYN is accepted, but
  the kernel validates the MD5 option during the handshake — so the
  per-address key used for static peers can never be installed in time.
  A mismatch is therefore invisible at the BGP layer: the kernel drops
  the SYN, no peer is ever materialized, and the DUT logs nothing.

  Config files:
  - z1.yaml:        DUT — SENDERS carries `password`, listen-range 192.168.0.0/24
  - z1-nopass.yaml: same DUT with the group password removed
  - z2.yaml:        client, matching tcp-md5 password
  - z2-wrong.yaml:  client, mismatched tcp-md5 password

  Scenario: Establish an MD5-authenticated dynamic session
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

  Scenario: A mismatched password never materializes a peer
    Given the test topology exists
    # The kernel drops the SYN before accept(), so this is not a
    # rejected session — it is no session at all: the DUT must not
    # even have a peer entry for the client.
    When I apply config "z2-wrong.yaml" to namespace "z2"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should not be "Established"
    And show command "show bgp summary" in namespace "z1" should not contain "192.168.0.2"
    And BGP route in "z1" does not have "10.0.2.2/32"

  Scenario: Restoring the matching password re-establishes the session
    Given the test topology exists
    When I apply config "z2.yaml" to namespace "z2"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP route in "z1" has "10.0.2.2/32"

  Scenario: Clearing the group password retracts the prefix key
    Given the test topology exists
    # With the DUT no longer expecting MD5 and the client still signing,
    # the handshake cannot complete — proving the key was really
    # retracted from the listener rather than lingering.
    When I apply config "z1-nopass.yaml" to namespace "z1"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should not be "Established"
    And show command "show bgp summary" in namespace "z1" should not contain "192.168.0.2"

  Scenario: Restoring the group password re-installs the prefix key
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
