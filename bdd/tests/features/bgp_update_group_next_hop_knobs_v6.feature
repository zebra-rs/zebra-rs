@serial
@bgp_update_group_next_hop_knobs_v6
Feature: Per-neighbor next-hop knobs must shard the IPv6-unicast update-group (IPv6)
  As a network operator
  I want `afi-safi ipv6 next-hop-self` and `afi-safi ipv6 next-hop-unchanged`
  to take effect per neighbor even when several neighbors share one
  update-group
  So that a reflector or an IXP router whose neighbors sit on one segment
  sends each of them the next-hop its own configuration asks for.

  IPv6 twin of `bgp_update_group_next_hop_knobs`: the IPv6-unicast
  advertise path reads the per-neighbor knobs straight from the peer,
  but the update-group signature carried only their VPNv4 twins, so two
  neighbors that differ only in a knob shared one memoized canonical
  UPDATE and the lower-index member decided the NEXT_HOP for both.

  The knob placement is MIRRORED relative to the IPv4 feature: here the
  canonical (lower-address) member of each pair is the one WITHOUT the
  knob, so it is the knob-bearing neighbor that is handed the wrong
  next-hop — the opposite direction of the same defect.

  Test Topology (one bridge; z1 is the router under test):
  ```
  ┌───────────────────────────────────────────────────────────────────┐
  │                               br0                                 │
  └────┬──────────────┬──────────────┬──────────────┬──────────────┬──┘
   ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐
   │  z2   │      │  z3   │      │  z1   │      │  z4   │      │  z5   │
   │ iBGP  │      │ iBGP  │      │  DUT  │      │ eBGP  │      │ eBGP  │
   │ plain │      │nh-self│      │ 65001 │      │nh-unch│      │ 65003 │
   │  ::2  │      │  ::3  │      │  ::1  │      │  ::4  │      │  ::5  │
   └───────┘      └───────┘      └───────┘      └───────┘      └───────┘
  ```
  Session addresses are 2001:db8:60::N; router-ids 10.61.0.N. The knobs
  are on z1: `next-hop-self` toward z3, `next-hop-unchanged` toward z4.

  - z4 (eBGP) originates 2001:db8:40::/64; z1 forwards it to z2 and z3.
    z2 must keep next-hop 2001:db8:60::4, z3 must see 2001:db8:60::1 (self).
  - z2 (iBGP) originates 2001:db8:20::/64; z1 forwards it to z4 and z5.
    z4 must keep 2001:db8:60::2, z5 must see 2001:db8:60::1 (eBGP default).

  The prefixes are injected only after every session is Established, so
  every advertisement takes the event-driven (memoized) path and not the
  per-peer session-up dump.

  Config files:
  - z1.yaml: router under test, the four neighbors and their knobs.
  - z2.yaml / z2-network.yaml, z4.yaml / z4-network.yaml: originators,
    session only and with their network.
  - z3.yaml, z5.yaml: listeners.

  Scenario: Setup topology and establish all four sessions before any route exists
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8:60::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8:60::2/64" on bridge "br0"
    And I create namespace "z3" with IP "2001:db8:60::3/64" on bridge "br0"
    And I create namespace "z4" with IP "2001:db8:60::4/64" on bridge "br0"
    And I create namespace "z5" with IP "2001:db8:60::5/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I start zebra-rs in namespace "z5"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "z4.yaml" to namespace "z4"
    And I apply config "z5.yaml" to namespace "z5"
    Then BGP session in "z1" to "2001:db8:60::2" should eventually be "Established"
    And BGP session in "z1" to "2001:db8:60::3" should eventually be "Established"
    And BGP session in "z1" to "2001:db8:60::4" should eventually be "Established"
    And BGP session in "z1" to "2001:db8:60::5" should eventually be "Established"

  Scenario: Inject the routes once every session is up, so they take the event-driven path
    Given the test topology exists
    When I apply config "z4-network.yaml" to namespace "z4"
    And I apply config "z2-network.yaml" to namespace "z2"
    Then show command "show bgp ipv6" in namespace "z1" should eventually contain "2001:db8:40::/64"
    And show command "show bgp ipv6" in namespace "z1" should eventually contain "2001:db8:20::/64"

  Scenario: The plain iBGP neighbor keeps the eBGP next-hop (control)
    Given the test topology exists
    Then show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:40::/64"
    And BGP best path in "z2" for "2001:db8:40::/64" has next-hop "2001:db8:60::4"

  Scenario: The iBGP neighbor with next-hop-self in the same update-group receives z1 as the next-hop
    Given the test topology exists
    # z3 asks for next-hop-self. Sharing z2's canonical UPDATE hands it
    # the received next-hop, z4.
    Then show command "show bgp ipv6" in namespace "z3" should eventually contain "2001:db8:40::/64"
    And BGP best path in "z3" for "2001:db8:40::/64" has next-hop "2001:db8:60::1"

  Scenario: The eBGP neighbor with next-hop-unchanged keeps the originator's next-hop (control)
    Given the test topology exists
    Then show command "show bgp ipv6" in namespace "z4" should eventually contain "2001:db8:20::/64"
    And BGP best path in "z4" for "2001:db8:20::/64" has next-hop "2001:db8:60::2"

  Scenario: The plain eBGP neighbor in the same update-group receives z1 as the next-hop
    Given the test topology exists
    # z5 gets the eBGP default rewrite. Sharing z4's canonical UPDATE
    # hands it the originator's next-hop, z2.
    Then show command "show bgp ipv6" in namespace "z5" should eventually contain "2001:db8:20::/64"
    And BGP best path in "z5" for "2001:db8:20::/64" has next-hop "2001:db8:60::1"

  Scenario: Each next-hop knob puts its neighbor in its own IPv6-unicast update-group
    Given the test topology exists
    # Four neighbors, four distinct (peer type, ipv6 next-hop knob)
    # signatures in the IPv6-unicast family. IPv4 unicast is negotiated
    # by default on every session too, and an ipv6 knob must NOT shard
    # that family, so its two groups (one iBGP pair, one eBGP pair) stay:
    # 4 + 2 groups over 4 + 4 memberships. With the knobs missing from
    # the signature the IPv6 family also has only two groups (4 / 8).
    Then show command "show bgp update-group" in namespace "z1" should eventually contain "6 groups, 8 members."

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I stop zebra-rs in namespace "z5"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "z4"
    And I delete namespace "z5"
    And I delete bridge "br0"
    Then the test environment should be clean
