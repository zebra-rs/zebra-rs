@serial
@bgp_evpn_single_active_remote
Feature: EVPN single-active — a remote PE forwards to the signalled DF
  As a network operator running a single-active Ethernet Segment
  I want a remote ingress PE to send the segment's known unicast to the PE
  that advertised P=1, and to hold the PE that advertised B=1 as its
  pre-installed standby, so traffic follows a Designated-Forwarder change as
  soon as the roles are re-advertised instead of waiting for every MAC to be
  withdrawn and relearned somewhere else.

  This is the consuming half of the role signal (phase 3b; origination is
  phase 3a). The distinction it removes: before this, a remote PE inferred
  the forwarder from which PE happened to advertise the segment's MACs
  (`Bgp::es_sa_primary`), which has nothing to read before the CE has sourced
  a frame and follows a DF change only as those MACs move. That inference is
  kept as the fallback for a segment whose PEs do not signal, so an upgrade
  changes nothing until asked.

  Test Topology — z1 and z2 share segment es1 and both peer with z3, which is
  on no segment at all and therefore holds no Type-4: it cannot re-run the
  election and must read the role off the per-EVI A-D.
  ```
  ┌──────────────────────────────────────────────┐
  │                     br0                      │
  └──────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   z1    │     │   z2    │     │   z3    │  remote ingress PE
    │ .0.1/24 │     │ .0.2/24 │     │ .0.3/24 │  no ethernet-segment,
    │ pref 200│     │ pref 100│     │ vxlan10 │  no access port
    └─────────┘     └─────────┘     └─────────┘
         └── es1, single-active ──┘
  ```

  Scenario: Setup topology, EVPN sessions and the shared segment
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I apply config "z3-1.yaml" to namespace "z3"
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
    And I wait 12 seconds for BGP to operate
    Then BGP session in "z3" to "192.168.0.1" should be "Established"
    And BGP session in "z3" to "192.168.0.2" should be "Established"

  Scenario: The remote installs the signalled primary, with the backup behind it
    Given the test topology exists
    # z3 sees both PEs' per-EVI A-Ds with their roles.
    Then show command "show bgp evpn" in namespace "z3" should eventually contain "l2-attr:P:mtu0"
    And show command "show bgp evpn" in namespace "z3" should eventually contain "l2-attr:B:mtu0"
    # ... and forms the segment's group with the P=1 PE (z1, preference 200)
    # at slot 0 — the only member a single-active datapath forwards to — and
    # the B=1 PE behind it as the pre-installed standby.
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should eventually contain "bd 10: single-active primary 192.168.0.1, backup 192.168.0.2"
    # The choice is named as a signal, not a guess: the same line reads
    # `(inferred)` on a segment whose PEs do not advertise a role.
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should contain "(signalled)"

  Scenario: The remote follows a DF change without any MAC moving
    Given the test topology exists
    # Raise z2's preference above z1's. No MAC exists anywhere in this
    # topology — there is no CE — so the pre-existing inference has NOTHING
    # to go on and could not move the group at all. Only the signal can.
    When I apply config "z2-pref300.yaml" to namespace "z2"
    Then show command "show bgp evpn ethernet-segment" in namespace "z3" should eventually contain "bd 10: single-active primary 192.168.0.2, backup 192.168.0.1"
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should contain "(signalled)"
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should not contain "primary 192.168.0.1,"

  Scenario: Losing the primary's segment fails the group over to the backup
    Given the test topology exists
    # The DF's access port goes down: its ES routes come off the wire (RFC
    # 7432 §8.2 mass withdraw), so it leaves the group entirely and the PE
    # that advertised B=1 is what remains.
    When I execute "ip link set host0 down" in namespace "z2"
    Then show command "show bgp evpn ethernet-segment" in namespace "z3" should eventually contain "bd 10: single-active primary 192.168.0.1"
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should not contain "192.168.0.2"
    # ... and it comes back when the port does.
    When I execute "ip link set host0 up" in namespace "z2"
    Then show command "show bgp evpn ethernet-segment" in namespace "z3" should eventually contain "bd 10: single-active primary 192.168.0.2, backup 192.168.0.1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
