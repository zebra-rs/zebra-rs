@serial
@bgp_dynamic_nbr_bfd
Feature: BFD follows a dynamic neighbor from accept to reap
  As a network operator
  I want `router bgp bfd enabled` to cover listen-range peers
  So a dynamic session gets BFD as soon as it is accepted, and loses it when the peer goes.

  Test Topology (z1 is the DUT):
  ```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐
   │   z2    │ i1────────────i1 │   z1    │
   │ AS65002 │   (in range)     │ AS65001 │
   │ .0.2    │                  │ .0.1    │
   └─────────┘                  └─────────┘
  ```

  z1 has no static neighbors and an instance-wide `bfd enabled true`.
  z2 is a static eBGP neighbor with `bfd enabled true`. A BFD session is
  Up only once the other end transmits, so z2 reaching Up proves z1
  subscribed a session for its dynamic peer. The Up step matches the
  session by interface, and a multihop session has none, so it also
  pins z2's session to single-hop.

  Config files:
  - z1.yaml:       DUT — listen-range 192.168.0.0/24 → group PEERS, instance-wide BFD
  - z2.yaml:       in-range client, static neighbor to .0.1 with BFD
  - z2-nonbr.yaml: the client with its neighbor deleted

  Scenario: Setup topology and establish the dynamic session
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z2" interface "i1" to namespace "z1" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z2" to "192.168.0.1" should eventually be "Established"
    And BGP session in "z1" to "192.168.0.2" should eventually be "Established"

  Scenario: The accepted dynamic peer brings its BFD session up
    Given the test topology exists
    # The accept path subscribes the session. It used to wait for an
    # unrelated BFD config change or address event, so z1 had no
    # session and z2's stayed Down. z2's `bfd` leaves are applied before its
    # `remote-as`, so they subscribed while the new peer was still iBGP
    # by default; only an address event landing after the commit
    # re-keyed that session to single-hop.
    Then bfd session in namespace "z1" on interface "i1" should be up
    And bfd session in namespace "z2" on interface "i1" should be up

  Scenario: Reaping the dynamic peer removes its BFD session
    Given the test topology exists
    # Deleting z2's neighbor ends the session, so z1 reaps the dynamic
    # peer. The reaper unsubscribes its BFD session: a session left
    # behind would stay listed (Down) and keep probing 192.168.0.2.
    # z2's whole-neighbor delete releases its own session too.
    When I apply config "z2-nonbr.yaml" to namespace "z2"
    Then show command "show bgp summary" in namespace "z1" should eventually not contain "192.168.0.2"
    And show command "show bfd peers" in namespace "z1" should eventually not contain "192.168.0.2"
    And show command "show bfd peers" in namespace "z2" should eventually not contain "192.168.0.1"

  Scenario: A re-accepted dynamic peer brings BFD up again
    Given the test topology exists
    # No address event follows this commit, so z2's session is
    # single-hop only if its `remote-as` re-keyed it.
    When I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Established"
    And bfd session in namespace "z2" on interface "i1" should be up
    And bfd session in namespace "z1" on interface "i1" should be up

  # Pure P2P topology (no bridge): deleting each namespace destroys the
  # veth pair ends it holds, so only daemons and namespaces need teardown.
  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
