@serial
@bgp_dynamic_neighbors
Feature: BGP dynamic neighbors materialize passive peers from a listen-range
  As a network operator
  I want `router bgp dynamic-neighbors listen-range <prefix> neighbor-group <G>`
  So sessions from an authorized source prefix establish without per-peer config.

  Test Topology (z1 is the DUT; only z2's subnet is range-authorized):
  ```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
   │   z2    │ i1────────────i1 │   z1    │ i2────────────i1 │   z3    │
   │ AS65002 │   (in range)     │ AS65001 │  (out of range)  │ AS65002 │
   │ .0.2    │                  │.0.1 .1.1│                  │ .1.3    │
   └─────────┘                  └─────────┘                  └─────────┘
  ```

  z1 has NO static neighbors. Its listen-range 192.168.0.0/24 binds
  neighbor-group SENDERS (remote-as 65002, ipv4 enabled), so z2's inbound
  connection materializes a passive peer that must reach Established and
  exchange routes in both directions (regression pin for PR #2044, where
  the materialized peer was left in Idle and every connection was
  dropped). z3 runs the same client config from 192.168.1.3 — outside
  the range — and must be refused at accept time with no peer state.

  Config files:
  - z1.yaml: DUT — group SENDERS + listen-range 192.168.0.0/24, originates 10.0.1.1/32
  - z2.yaml: in-range client, static neighbor to .0.1, originates 10.0.2.2/32
  - z3.yaml: out-of-range client, static neighbor to .1.1, originates 10.0.3.3/32

  Scenario: Setup topology and establish the dynamic session
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I create namespace "z3"
    And I connect namespace "z2" interface "i1" to namespace "z1" interface "i1"
    And I connect namespace "z1" interface "i2" to namespace "z3" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z1" to "192.168.0.2" should be "Established"
    And show command "show bgp summary" in namespace "z1" should contain "192.168.0.2"

  Scenario: Routes flow in both directions over the dynamic session
    Given the test topology exists
    Then BGP route in "z1" has "10.0.2.2/32"
    And BGP route in "z2" has "10.0.1.1/32"

  Scenario: A source outside every listen-range is refused without peer state
    Given the test topology exists
    # z3's TCP connect is accepted by the kernel, but the LPM miss makes
    # z1 drop the stream before any OPEN exchange — z3 never leaves the
    # connect/retry cycle, and z1 materializes nothing for 192.168.1.3.
    Then BGP session in "z3" to "192.168.1.1" should not be "Established"
    And show command "show bgp summary" in namespace "z1" should not contain "192.168.1.3"
    And BGP route in "z1" does not have "10.0.3.3/32"

  Scenario: The client can hard-reset and re-establish the dynamic session
    Given the test topology exists
    # Pre-#2044 every reconnect was dropped: the very first inbound
    # stream materialized the peer, then died in Idle forever.
    When I wait 10 seconds
    And I run "clear bgp ipv4 neighbor 192.168.0.1" in namespace "z2"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP route in "z1" has "10.0.2.2/32"
    And BGP route in "z2" has "10.0.1.1/32"

  Scenario: A DUT-side clear frees the peer and the next connect re-materializes it
    Given the test topology exists
    # Clearing on z1 ends the session of a Dynamic-origin peer, which
    # the instance GCs (freeing its listen-limit slot); z2's redial then
    # re-materializes a fresh peer through the same accept path.
    When I wait 10 seconds
    And I run "clear bgp ipv4 neighbor 192.168.0.2" in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP route in "z1" has "10.0.2.2/32"
    And BGP route in "z2" has "10.0.1.1/32"

  # Pure P2P topology (no bridge): deleting each namespace destroys the
  # veth pair ends it holds, so only daemons and namespaces need teardown.
  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    Then the test environment should be clean
