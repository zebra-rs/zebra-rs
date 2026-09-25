@serial
@nd_vrf_move
Feature: Router Advertisements survive enslaving the interface into a VRF
  As an operator running IPv6 RA on an interface that later joins a VRF
  I want `interface i1 vrf blue` to leave the interface advertising
  so that moving a link into a VRF is a routing-table change and not a
  silent loss of RA on that link.

  ND is a single process-wide instance — unlike OSPF / IS-IS / BGP it is
  not re-spawned per VRF — so it has to follow interfaces across VRF
  boundaries itself. It used to subscribe to the RIB with the default
  `vrf_id 0` binding, and `Rib::iter_link_subs` only delivers a link
  event to subscribers whose `vrf_id` matches the link's VRF. RIB reports
  a live cross-VRF move as `api_link_del_vrf(ifindex, old)` followed by
  `api_link_add_vrf(link, new)`, so a vrf-0 subscriber saw only the
  `LinkDel` half: `Nd::process_link_del` released the sender and the
  matching `LinkAdd` — the one that would have re-applied the operator's
  name-keyed RA config — was addressed to the VRF's subscribers instead
  and never arrived. RA stopped for good, and `show ipv6 nd interface i1`
  stopped reporting the interface at all.

  This is the regression test for that: it fails on a vrf-0 subscription
  and passes with `global_links`.

  Test Topology (point-to-point veth, link-local only):
  ```
        (i1)                                   (i1)
    ┌────┴────┐                            ┌────┴────┐
    │   z1    │────────── P2P ─────────────│   z2    │
    │ RA on   │       fe80:: <-> fe80::    │ RA on   │
    │ vrf blue│                            │ default │
    └─────────┘                            └─────────┘
  ```

  z2 exists only to hold the far end of the veth up (so i1 on z1 keeps
  IFF_LOWER_UP and is not suspended by the link-state gate) and to send
  RAs of its own so z1's receive counters move.

  Scenario: Setup topology
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2-full.yaml" to namespace "z2"
    And I wait 2 seconds

  Scenario: RA keeps running after the interface is enslaved into a VRF
    Given the test topology exists
    When I apply config "z1-full.yaml" to namespace "z1"
    # Baseline: RA is armed and has actually transmitted. The first
    # unsolicited RA lands within MAX_INITIAL_RTR_ADVERT_INTERVAL (16s),
    # so "last multicast never" has to clear on its own.
    Then show command "show ipv6 nd interface i1" in namespace "z1" should contain "Router advertisement: enabled"
    And show command "show ipv6 nd interface i1" in namespace "z1" should eventually not contain "last multicast never"

    # The move itself. A surgical `set` rather than a config file: a
    # config FILE is a whole-config replace, which would rewrite the RA
    # line instead of leaving it alone across the move.
    When I apply command "set interface i1 vrf blue" in namespace "z1"
    And I wait 3 seconds

    # The regression. On a vrf-0 subscription the sender, the counters
    # and the neighbor records are all released by the unpaired
    # LinkDel, so i1 drops out of `show ipv6 nd` entirely and this line
    # fails. With `global_links` the paired LinkAdd arrives, the
    # name-keyed `send-advertisements` config is re-applied, and the
    # interface is advertising again.
    Then show command "show ipv6 nd interface i1" in namespace "z1" should eventually contain "Router advertisement: enabled"

    # ... and the restarted sender actually reaches the wire from inside
    # the VRF. The egress ifindex is pinned with an IPV6_PKTINFO cmsg,
    # so the send does not depend on a VRF route lookup; this asserts
    # that end to end rather than assuming it.
    And show command "show ipv6 nd interface i1" in namespace "z1" should eventually not contain "last multicast never"

    # The operator's intent is still on record under the interface name,
    # which is what made the recovery possible.
    And show command "show ipv6 nd" in namespace "z1" should contain "i1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
