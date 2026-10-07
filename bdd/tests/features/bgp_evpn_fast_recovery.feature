@serial
@bgp_evpn_fast_recovery
Feature: EVPN single-active — carve at an announced instant (RFC 9722)
  As a network operator running a single-active Ethernet Segment
  I want a PE joining the segment to announce WHEN it will run DF election,
  and the PEs already there to hold their roles until that instant, so the
  segment changes forwarder once, together, instead of each PE moving whenever
  BGP happened to deliver.

  Without this, the joining PE waits out a local timer while the incumbent
  re-carves the moment the new Type-4 arrives — and a single-active segment
  spends the difference with either no Designated Forwarder or two of them.
  One drops frames for that window; the other duplicates them and can loop.

  The hold is only taken when the whole segment asks for it: the capability
  rides the DF Election extended community and synchronized carving needs
  every PE to signal it (RFC 9722 §2.3), exactly as AC-DF does. The last
  scenario is that control.

  `peering-time` is 20 s here, far above the 3 s default, purely so the window
  in which the role is held is wide enough to assert on rather than a race.

  Test Topology — two PEs on segment es1, each with a CE-facing port in
  bridge domain 10. z2 starts off the segment and joins:
  ```
  ┌─────────────────────────────────┐
  │               br0               │
  └───────┬─────────────────┬───────┘
     ┌────┴────┐       ┌────┴────┐
     │   z1    │       │   z2    │  es1, single-active, fast-recovery
     │ .0.1/24 │       │ .0.2/24 │  peering-time 20s
     │ pref 100│       │ pref 300│  (z2 joins mid-feature)
     └─────────┘       └─────────┘
  ```

  Scenario: Setup topology with z1 alone on the segment
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-noes.yaml" to namespace "z2"
    And I execute "ip link add br10 address 02:00:00:00:fe:01 type bridge" in namespace "z1"
    And I execute "ip link set vxlan10 master br10" in namespace "z1"
    And I execute "ip link set br10 up" in namespace "z1"
    And I execute "ip link add host0 type dummy" in namespace "z1"
    And I execute "ip link set host0 master br10" in namespace "z1"
    And I execute "ip link set host0 up" in namespace "z1"
    And I execute "ip link add br10 address 02:00:00:00:fe:02 type bridge" in namespace "z2"
    And I execute "ip link set vxlan10 master br10" in namespace "z2"
    And I execute "ip link set br10 up" in namespace "z2"
    And I execute "ip link add host0 type dummy" in namespace "z2"
    And I execute "ip link set host0 master br10" in namespace "z2"
    And I execute "ip link set host0 up" in namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    # Alone on the segment, z1 is the Designated Forwarder and the datapath
    # has been told so.
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "bd 10: DF"

  Scenario: A joining PE announces its carving instant and the incumbent holds
    Given the test topology exists
    When I apply config "z2-join.yaml" to namespace "z2"
    # z1 sees the whole segment asking for synchronized carving...
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "Fast recovery: advertised, in effect (2 of 2 PEs advertise it)"
    # ... and adopts the instant z2 announced, rather than one of its own.
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "a peer's"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should contain "roles held until then"
    # The election has already moved — z2's preference is higher — but the
    # datapath is still being told z1 is the forwarder. That gap between the
    # election and what is programmed is the entire mechanism.
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should contain "bd 10: DF"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should not contain "bd 10: non-DF"
    # z2, which is gaining the role, is waiting on an instant of its own making.
    And show command "show bgp evpn ethernet-segment" in namespace "z2" should eventually contain "ours"

  Scenario: At the announced instant both PEs carve
    Given the test topology exists
    # 20 s after the announcement the hold ends: z1 hands the role over and
    # z2 takes it. The outgoing PE steps down a skew ahead of the instant, so
    # the two never overlap.
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "bd 10: non-DF"
    And show command "show bgp evpn ethernet-segment" in namespace "z2" should eventually contain "bd 10: DF"
    # The announcement is spent: it is honoured once, so the segment is not
    # left waiting on an instant everybody has already carved at.
    #
    # The wait is load-bearing. z1 steps down a skew BEFORE the instant and
    # retires the carve AT it, so the assertions above can be satisfied up to
    # a skew before this line becomes true — and the only negative form of
    # this step is immediate. Without the wait this rides a millisecond-scale
    # ordering between two timers.
    And I wait 2 seconds
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should not contain "roles held until then"

  Scenario: Without unanimity nobody holds a role
    Given the test topology exists
    # Take z2 off the segment, let z1 become the forwarder again, then have z2
    # rejoin with the SAME preference but no fast-recovery. The capability is
    # no longer unanimous, so no PE may hold a role for an announced instant.
    When I apply config "z2-noes.yaml" to namespace "z2"
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "bd 10: DF"
    When I apply config "z2-nofr.yaml" to namespace "z2"
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "not in effect"
    # The role moves at once, with no instant adopted at all.
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "bd 10: non-DF"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should not contain "roles held until then"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
