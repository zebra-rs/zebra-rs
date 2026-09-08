@serial
@bgp_update_group_next_hop_knobs
Feature: Per-neighbor next-hop knobs must shard the IPv4-unicast update-group (IPv4)
  As a network operator
  I want `afi-safi ipv4 next-hop-self` and `afi-safi ipv4 next-hop-unchanged`
  to take effect per neighbor even when several neighbors share one
  update-group
  So that a reflector or an IXP router whose neighbors sit on one segment
  sends each of them the next-hop its own configuration asks for.

  An update-group is keyed by a signature of every per-peer input to the
  egress transform; members share one memoized canonical UPDATE. The
  IPv4-unicast advertise path honors the per-neighbor next-hop-self and
  next-hop-unchanged knobs, but the signature carried only their VPNv4
  twins. Two iBGP neighbors that differ only in `next-hop-self` — or two
  eBGP neighbors that differ only in `next-hop-unchanged` — therefore
  shared a group, and whichever had the lower peer index decided the
  NEXT_HOP for both.

  Test Topology (one bridge; z1 is the router under test):
  ```
  ┌───────────────────────────────────────────────────────────────────┐
  │                               br0                                 │
  └────┬──────────────┬──────────────┬──────────────┬──────────────┬──┘
   ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐
   │  z2   │      │  z3   │      │  z1   │      │  z4   │      │  z5   │
   │ iBGP  │      │ iBGP  │      │  DUT  │      │ eBGP  │      │ eBGP  │
   │nh-self│      │ plain │      │ 65001 │      │ 65002 │      │nh-unch│
   │  .2   │      │  .3   │      │  .1   │      │  .4   │      │  .5   │
   └───────┘      └───────┘      └───────┘      └───────┘      └───────┘
  ```
  Session addresses are 192.168.60.N; router-ids 10.60.0.N. The knobs
  are on z1: `next-hop-self` toward z2, `next-hop-unchanged` toward z5.

  - z4 (eBGP) originates 10.40.0.0/24; z1 forwards it to z2 and z3.
    z2 must see next-hop 192.168.60.1 (self), z3 must keep 192.168.60.4.
  - z2 (iBGP) originates 10.20.0.0/24; z1 forwards it to z4 and z5.
    z4 must see next-hop 192.168.60.1 (eBGP default), z5 must keep
    192.168.60.2.
  In each pair the lower-address neighbor is the canonical member of the
  wrongly shared group, so the second member of each pair is the one
  that received the wrong next-hop.

  The prefixes are injected only after every session is Established:
  the session-up dump builds each peer's UPDATE on its own, so a route
  that arrived before a peer came up would reach it correctly and mask
  the defect. Only the event-driven path goes through the shared memo.

  Config files:
  - z1.yaml: router under test, the four neighbors and their knobs.
  - z2.yaml / z2-network.yaml, z4.yaml / z4-network.yaml: originators,
    session only and with their network.
  - z3.yaml, z5.yaml: listeners.

  Scenario: Setup topology and establish all four sessions before any route exists
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.60.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.60.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.60.3/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.60.4/24" on bridge "br0"
    And I create namespace "z5" with IP "192.168.60.5/24" on bridge "br0"
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
    Then BGP session in "z1" to "192.168.60.2" should eventually be "Established"
    And BGP session in "z1" to "192.168.60.3" should eventually be "Established"
    And BGP session in "z1" to "192.168.60.4" should eventually be "Established"
    And BGP session in "z1" to "192.168.60.5" should eventually be "Established"

  Scenario: Inject the routes once every session is up, so they take the event-driven path
    Given the test topology exists
    When I apply config "z4-network.yaml" to namespace "z4"
    And I apply config "z2-network.yaml" to namespace "z2"
    Then show command "show bgp" in namespace "z1" should eventually contain "10.40.0.0/24"
    And show command "show bgp" in namespace "z1" should eventually contain "10.20.0.0/24"

  Scenario: The iBGP neighbor with next-hop-self receives z1 as the next-hop (control)
    Given the test topology exists
    Then show command "show bgp" in namespace "z2" should eventually contain "10.40.0.0/24"
    And BGP best path in "z2" for "10.40.0.0/24" has next-hop "192.168.60.1"

  Scenario: The plain iBGP neighbor in the same update-group keeps the eBGP next-hop
    Given the test topology exists
    # z3 has no next-hop knob: an iBGP-forwarded eBGP route keeps the
    # received next-hop, z4. Sharing z2's canonical UPDATE hands it z1.
    Then show command "show bgp" in namespace "z3" should eventually contain "10.40.0.0/24"
    And BGP best path in "z3" for "10.40.0.0/24" has next-hop "192.168.60.4"

  Scenario: The plain eBGP neighbor receives z1 as the next-hop (control)
    Given the test topology exists
    Then show command "show bgp" in namespace "z4" should eventually contain "10.20.0.0/24"
    And BGP best path in "z4" for "10.20.0.0/24" has next-hop "192.168.60.1"

  Scenario: The eBGP neighbor with next-hop-unchanged in the same update-group keeps the originator's next-hop
    Given the test topology exists
    # z5 asks for the received next-hop, z2. Sharing z4's canonical
    # UPDATE hands it z1 — the eBGP default rewrite.
    Then show command "show bgp" in namespace "z5" should eventually contain "10.20.0.0/24"
    And BGP best path in "z5" for "10.20.0.0/24" has next-hop "192.168.60.2"

  Scenario: Each next-hop knob puts its neighbor in its own update-group
    Given the test topology exists
    # Four neighbors, four distinct (peer type, next-hop knob) signatures.
    # With the knobs missing from the signature there are only two groups.
    Then show command "show bgp update-group" in namespace "z1" should eventually contain "4 groups, 4 members."

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
