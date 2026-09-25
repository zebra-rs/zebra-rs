@serial
@bgp_evpn_single_active_no_forwarder
Feature: EVPN single-active — a segment with no forwarder withholds its MACs
  As a network operator running a single-active Ethernet Segment
  I want a remote PE that has been told "not me" by every PE it could send to
  to install those MACs NOWHERE, so traffic is never delivered to a PE that
  explicitly declared itself non-designated — where a non-DF blocks its access
  port in both directions and the frame dies anyway.

  The trap this covers: a Type-2 remains perfectly valid after the PE that
  advertised it loses the election. Withholding the nexthop group is not
  enough on its own — an absent group means "install each MAC toward the PE
  that advertised it", which is precisely the PE that said not to use it. The
  blocked state therefore has to be represented separately from a deleted
  group, all the way into the RIB.

  Test Topology — z2 and z4 are on segment es1 with NO access port: they vote
  in the DF election but never originate a per-EVI A-D, so they are never in
  z3's nexthop group. z1 has the only port in bridge domain 10 and is
  therefore the group's only member — which is how the group reaches a state
  where every member advertises P=0/B=0.
  ```
  ┌──────────────────────────────────────────────────────────┐
  │                           br0                            │
  └────┬───────────────┬───────────────┬───────────────┬─────┘
   ┌───┴───┐       ┌───┴───┐       ┌───┴───┐       ┌───┴───┐
   │  z1   │       │  z2   │       │  z4   │       │  z3   │
   │ .0.1  │       │ .0.2  │       │ .0.4  │       │ .0.3  │
   │ port  │       │ no    │       │ no    │       │remote │
   │ host0 │       │ port  │       │ port  │       │ only  │
   │pref100│       │pref ? │       │pref ? │       │       │
   └───────┘       └───────┘       └───────┘       └───────┘
       └──────── es1, single-active ─────┘
  ```

  Scenario: Setup topology with z1 as the Designated Forwarder
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.0.4/24" on bridge "br0"
    And I create namespace "z5" with IP "192.168.0.5/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I start zebra-rs in namespace "z5"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-low.yaml" to namespace "z2"
    And I apply config "z3-1.yaml" to namespace "z3"
    And I apply config "z4-low.yaml" to namespace "z4"
    And I apply config "z5-1.yaml" to namespace "z5"
    And I execute "ip link add br10 address 02:00:00:00:fe:01 type bridge" in namespace "z1"
    And I execute "ip link set vxlan10 master br10" in namespace "z1"
    And I execute "ip link set br10 up" in namespace "z1"
    And I execute "ip link add host0 type dummy" in namespace "z1"
    And I execute "ip link set host0 master br10" in namespace "z1"
    And I execute "ip link set host0 up" in namespace "z1"
    And I execute "ip link add br10 address 02:00:00:00:fe:05 type bridge" in namespace "z5"
    And I execute "ip link set vxlan10 master br10" in namespace "z5"
    And I execute "ip link set br10 up" in namespace "z5"
    And I execute "ip link add host0 type dummy" in namespace "z5"
    And I execute "ip link set host0 master br10" in namespace "z5"
    And I execute "ip link set host0 up" in namespace "z5"
    And I execute "ip link add br10 address 02:00:00:00:fe:03 type bridge" in namespace "z3"
    And I execute "ip link set vxlan10 master br10" in namespace "z3"
    And I execute "ip link set br10 up" in namespace "z3"
    And I wait 12 seconds for BGP to operate
    Then BGP session in "z3" to "192.168.0.1" should be "Established"
    And BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z1" to "192.168.0.4" should be "Established"
    And BGP session in "z1" to "192.168.0.5" should be "Established"

  Scenario: The control — while z1 is the DF its MAC installs on the remote
    Given the test topology exists
    # A CE MAC parked on z1's access port. z1 is the DF (preference 100
    # against z2's 50 and z4's 40), so it advertises P=1 and z3 installs the
    # MAC toward it.
    When I execute "bridge fdb add aa:bb:cc:dd:ee:01 dev host0 master static" in namespace "z1"
    # A second CE MAC, this one on z5 — another PE attached to the SAME
    # segment. z1 therefore learns it as a MAC on its OWN segment.
    And I execute "bridge fdb add aa:bb:cc:dd:ee:05 dev host0 master static" in namespace "z5"
    Then show command "show bgp evpn" in namespace "z3" should eventually contain "aa:bb:cc:dd:ee:01"
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should eventually contain "bd 10: single-active primary 192.168.0.1"
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should contain "(signalled)"
    And bridge fdb "vxlan10" in namespace "z3" should eventually contain "aa:bb:cc:dd:ee:01"

  Scenario: Every group member non-designated withholds the MAC
    Given the test topology exists
    # z2 and z4 raise their preferences above z1's. Neither has a port, so
    # neither joins z3's group — but both outrank z1 in the election, leaving
    # z1 (the group's only member) advertising P=0/B=0.
    When I apply config "z2-high.yaml" to namespace "z2"
    And I apply config "z4-high.yaml" to namespace "z4"
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "bd 10: non-designated"
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should eventually contain "single-active, no forwarder (MACs withheld)"
    # The Type-2 is STILL THERE and still valid — that is the whole point.
    # Nothing about the MAC route changed; only the role did.
    And show command "show bgp evpn" in namespace "z3" should contain "aa:bb:cc:dd:ee:01"
    # ... and the MAC must come out of the forwarding table anyway. A deleted
    # group would have reinstalled it toward 192.168.0.1 — the PE that just
    # said not to use it.
    #
    # The `no forwarder (MACs withheld)` assertion above already waited for
    # the state to converge; this waits out the netlink round trip behind it,
    # because the only negative form of this step is immediate.
    And I wait 3 seconds
    And bridge fdb "vxlan10" in namespace "z3" should not contain "aa:bb:cc:dd:ee:01"

  Scenario: Blocking a segment never withdraws MACs on this PE's own segment
    Given the test topology exists
    # z1 is attached to es1 and is blocked in the same breath: its group is
    # built from the OTHER PEs' per-EVI A-Ds, which here is z5 alone, and z5
    # advertises P=0/B=0 just as z1 does. But "no forwarder" is a statement
    # about reaching the segment through a remote PE — it says nothing about
    # the segment z1 is itself attached to, where the path is z1's own access
    # port (RFC 7432 §8.4). On the PE that is the Designated Forwarder this
    # is not a nicety: every other member correctly says "not me", so a
    # blanket block would tear out the local rows of the one PE that is
    # actually forwarding.
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "single-active, no forwarder (MACs withheld)"
    # z5's CE MAC is on z1's own segment and must survive that block.
    And bridge fdb "vxlan10" in namespace "z1" should eventually contain "aa:bb:cc:dd:ee:05"
    # (This backend has no cradle, so the row is programmed toward the
    # advertising PE; with the cradle datapath the same entry installs on
    # z1's own access port instead. What is proven here is the precedence —
    # a MAC on our own segment is never withheld by a remote group's
    # verdict.)

  Scenario: A partly signalled segment falls back instead of withholding
    Given the test topology exists
    # The rollout case. z5 goes back to `role-signaling inferred` — an older
    # release, or a PE not migrated yet — while z1 still advertises P=0/B=0
    # and the election still puts the DF on a portless PE. The group is now
    # only PARTLY signalled: reading "no member claims primary" as "withhold
    # the group" would blackhole a segment that is forwarding perfectly well,
    # because the silent PE may be the very one forwarding.
    #
    # So the roles must not be read at all until every member signals, the
    # way RFC 8584 §4 gates AC-DF — and the remote goes back to the inference
    # it used before anyone was upgraded.
    When I apply config "z5-inferred.yaml" to namespace "z5"
    Then show command "show bgp evpn ethernet-segment" in namespace "z3" should eventually contain "(inferred)"
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should not contain "no forwarder"
    # The MAC that the blocked state had withheld is forwarding again.
    And bridge fdb "vxlan10" in namespace "z3" should eventually contain "aa:bb:cc:dd:ee:01"
    # Put z5 back so the scenarios below see a fully signalled segment.
    When I apply config "z5-1.yaml" to namespace "z5"
    Then show command "show bgp evpn ethernet-segment" in namespace "z3" should eventually contain "no forwarder (MACs withheld)"

  Scenario: Restoring a forwarder reinstalls the withheld MAC
    Given the test topology exists
    # z1 outranks them again, advertises P=1, and the MAC that was never
    # withdrawn comes straight back — no relearn, no re-advertisement.
    When I apply config "z2-low.yaml" to namespace "z2"
    And I apply config "z4-low.yaml" to namespace "z4"
    Then show command "show bgp evpn ethernet-segment" in namespace "z3" should eventually contain "bd 10: single-active primary 192.168.0.1"
    And bridge fdb "vxlan10" in namespace "z3" should eventually contain "aa:bb:cc:dd:ee:01"

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
