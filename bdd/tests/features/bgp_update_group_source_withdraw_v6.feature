@serial
@bgp_update_group_source_withdraw_v6
Feature: Withdrawing a route from its source member must not clobber a group-mate's pending advertisement (IPv6)
  As a network operator
  I want a reflector whose best path for a prefix flips to a client's own
  path to advertise the new path to that client's group-mates
  So that the group-mates follow the reflector's selection instead of
  keeping a next-hop the reflector no longer prefers.

  An update-group shares one pending-advertisement cache. When the best
  path for a prefix changes, the batch runs one outcome per member: an
  advertisement, queued into the shared cache for the next flush, or a
  per-peer withdraw — for the member the new best was learned from
  (split-horizon), which is withdrawn what it held before. That withdraw
  must leave the shared cache alone: the entry it would remove is the one
  just queued for the other members.

  The GATE: the IPv6 batch withdraw has no such guard. When the reflector's
  best for a prefix flips to a path learned from one client, the batch
  queues the new advertisement for the other member of the group and then
  runs the source client's per-peer withdraw — which pops that queued
  entry out of the group's cache. The other client's Adj-RIB-Out at the
  reflector says "via the new source" while the wire still says "via the
  old one", and nothing repeats the announcement until the best changes
  again; once the old path is gone that client forwards into a hole.

  Test Topology (one bridge; z1 is the reflector):
  ```
  ┌───────────────────────────────────────────────────────┐
  │                          br0                          │
  └────┬──────────────┬──────────────┬──────────────┬─────┘
   ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐
   │  z2   │      │  z3   │      │  z1   │      │  z4   │
   │client │      │client │      │  RR   │      │ eBGP  │
   │  ::2   │      │  ::3   │      │  ::1   │      │  ::4   │
   └───────┘      └───────┘      └───────┘      └───────┘
  ```
  Session addresses are 2001:db8:80::N; router-ids 10.81.0.N. z2 and z3 are
  clients of z1 and share its local address, so they sit in one
  update-group with z2 as the lower-index member.

  - z4 (eBGP, AS 65002) originates 2001:db8:85::/64; z1 reflects it to z2 and
    z3, which both hold it with next-hop 2001:db8:80::4.
  - z3 then originates 2001:db8:85::/64 itself. Its empty AS_PATH beats z4's
    one-hop path, so z1's best flips to z3's path: z2 must be advertised
    the prefix with next-hop 2001:db8:80::3, while z3 — the source — is
    withdrawn what it held.
  - z4 withdraws the prefix: z2 must still hold it via z3.

  Config files:
  - z1.yaml: reflector; z2.yaml, z3.yaml: clients (z3-network.yaml adds
    z3's own prefix); z4.yaml / z4-withdrawn.yaml: the eBGP originator.

  Scenario: Setup topology; both clients hold the prefix via the eBGP neighbor
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8:80::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8:80::2/64" on bridge "br0"
    And I create namespace "z3" with IP "2001:db8:80::3/64" on bridge "br0"
    And I create namespace "z4" with IP "2001:db8:80::4/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "z4.yaml" to namespace "z4"
    Then BGP session in "z1" to "2001:db8:80::2" should eventually be "Established"
    And BGP session in "z1" to "2001:db8:80::3" should eventually be "Established"
    And BGP session in "z1" to "2001:db8:80::4" should eventually be "Established"
    And show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:85::/64"
    And show command "show bgp ipv6" in namespace "z3" should eventually contain "2001:db8:85::/64"
    And BGP best path in "z2" for "2001:db8:85::/64" has next-hop "2001:db8:80::4"
    And BGP best path in "z3" for "2001:db8:85::/64" has next-hop "2001:db8:80::4"

  Scenario: The reflector's best flips to z3's own path; z2 must be advertised the new path
    Given the test topology exists
    When I apply config "z3-network.yaml" to namespace "z3"
    # z1 now prefers z3's path (empty AS_PATH). The batch queues it for z2
    # and withdraws the old reflected route from z3, the source. That
    # withdraw must not pop z2's queued advertisement.
    Then show command "show bgp ipv6 2001:db8:85::/64" in namespace "z1" should eventually contain "2001:db8:80::3"
    And show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:80::3"
    And BGP best path in "z2" for "2001:db8:85::/64" has next-hop "2001:db8:80::3"

  Scenario: The eBGP originator withdraws; z2 keeps the prefix via z3
    Given the test topology exists
    When I apply config "z4-withdrawn.yaml" to namespace "z4"
    Then show command "show bgp ipv6 2001:db8:85::/64" in namespace "z1" should eventually not contain "2001:db8:80::4"
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:85::/64"
    And BGP best path in "z2" for "2001:db8:85::/64" has next-hop "2001:db8:80::3"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "z4"
    And I delete bridge "br0"
    Then the test environment should be clean
