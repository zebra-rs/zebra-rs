@serial
@bgp_lu_addpath_resend_v6
Feature: AddPath labeled-unicast peers must not re-send unchanged candidates to each other (IPv6)
  As a network operator
  I want two routers with AddPath labeled-unicast toward each other to
  settle after exchanging their paths
  So that they do not re-advertise the same candidates to each other on
  every UPDATE, forever, at line rate.

  The labeled-unicast AddPath fan-out sends every candidate to every
  AddPath peer on every best-path event and only then records it in the
  Adj-RIB-Out, discarding what was recorded before — so it cannot tell an
  unchanged candidate from a new one (the best-path-only branch does,
  via `same_advertised`). With AddPath in both directions and a prefix
  both routers hold, each UPDATE received makes the receiver fan its own
  candidate back, which makes the sender do the same: a re-send loop
  bounded only by the round-trip time.

  IPv6 labeled-unicast twin (`label-v6`).

  Test Topology (one bridge):
  ```
  ┌───────────────────────────────┐
  │              br0              │
  └────┬─────────────────────┬────┘
   ┌───┴───┐             ┌───┴───┐
   │  z1   │   AddPath   │  z2   │
   │ 65001 │ ◄─────────► │ 65002 │
   │  ::1  │  LU both  │  ::2  │
   └───────┘   directions └───────┘
  ```
  Session addresses are 2001:db8:90::N; router-ids 10.91.0.N. Both routers
  originate 2001:db8:95::/64 in labeled-unicast.

  Scenario: Setup topology; both routers hold both candidates
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8:90::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8:90::2/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "2001:db8:90::2" should eventually be "Established"
    And BGP session in "z2" to "2001:db8:90::1" should eventually be "Established"
    And show command "show bgp labeled-unicast" in namespace "z1" should eventually contain "2001:db8:95::/64"
    And show command "show bgp labeled-unicast" in namespace "z2" should eventually contain "2001:db8:95::/64"
    And show command "show bgp labeled-unicast" in namespace "z1" should eventually contain "65002"
    And show command "show bgp labeled-unicast" in namespace "z2" should eventually contain "65001"

  Scenario: The sessions settle instead of re-sending the unchanged candidates forever
    Given the test topology exists
    # Ten seconds after the exchange, the only traffic left should be
    # keepalives. A re-send loop delivers hundreds of UPDATEs per second.
    # (Counted on the receiving side: the daemon counts received messages
    # by type but never counts sent UPDATEs.)
    Then BGP neighbor "2001:db8:90::2" in "z1" receives fewer than 15 messages over 10 seconds
    And BGP neighbor "2001:db8:90::1" in "z2" receives fewer than 15 messages over 10 seconds

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
