@serial
@bgp_evpn_single_active_conflict
Feature: EVPN single-active — a disputed role keeps the incumbent forwarder
  As a network operator running a single-active Ethernet Segment
  I want a remote PE faced with two PEs both claiming to forward to keep
  sending to the one it was already using, and to say that the segment is in
  conflict, so a misconfiguration or a partitioned control plane does not
  also move established traffic to a different PE for no benefit.

  Two PEs claiming P=1 is a segment-level fault that no ingress PE can
  repair — both of them believe they forward, so neither is blocking its
  access port. The only question left is which of them THIS node uses, and
  moving an established flow buys nothing. With no incumbent among the
  claimants the lowest address decides instead, so remotes with no history
  still agree with one another.

  The conflict here is built the way it happens in the field rather than by
  hand: the two segment PEs stop seeing each other's Type-4 (a partitioned
  iBGP mesh, or a route reflector they no longer share), so each elects over
  a candidate set of one and both make themselves the Designated Forwarder.

  Test Topology — z3 is on no segment and peers with both, so it is the only
  node that sees the disagreement:
  ```
  ┌─────────────────────────────────────────────┐
  │                     br0                     │
  └──────┬───────────────┬───────────────┬──────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   z1    │     │   z2    │     │   z3    │
    │ .0.1/24 │ ... │ .0.2/24 │     │ .0.3/24 │  remote ingress PE
    │ pref 100│     │ pref 300│     │ no ES   │
    └─────────┘     └─────────┘     └─────────┘
         └── es1, single-active ──┘
             (session removed in the split scenario)
  ```

  Scenario: Setup topology with both PEs agreeing on z2 as the forwarder
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-full.yaml" to namespace "z1"
    And I apply config "z2-full.yaml" to namespace "z2"
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
    And I execute "ip link add br10 address 02:00:00:00:fe:03 type bridge" in namespace "z3"
    And I execute "ip link set vxlan10 master br10" in namespace "z3"
    And I execute "ip link set br10 up" in namespace "z3"
    And I wait 12 seconds for BGP to operate
    Then BGP session in "z3" to "192.168.0.1" should be "Established"
    And BGP session in "z3" to "192.168.0.2" should be "Established"

  Scenario: The remote follows the agreed forwarder and shows how it knows
    Given the test topology exists
    # Preference 300 makes z2 the DF, so it claims P and z1 claims B. Note
    # the incumbent is therefore the HIGHER address — which is what makes
    # the next scenario discriminating.
    Then show command "show bgp evpn ethernet-segment" in namespace "z3" should eventually contain "bd 10: single-active primary 192.168.0.2, backup 192.168.0.1 (signalled)"
    # The derived view behind that line: each PE's advertised role and the
    # copies of its route we are holding.
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should contain "192.168.0.2: role P"
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should contain "192.168.0.1: role B"
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should contain "[best]"
    # The generation is rendered, but its VALUE is not asserted anywhere in
    # this feature: it counts how many times the forwarder has moved,
    # including any transient during startup convergence — both PEs briefly
    # elect themselves before they have each other's Type-4 — so an absolute
    # number is an assertion about convergence ordering, which is a race.
    # Its consumer is a completion barrier, not a test.
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should contain "generation"

  Scenario: Both PEs claiming the role keeps the incumbent, not the lowest address
    Given the test topology exists
    # The segment PEs stop seeing each other. Each now elects over a
    # candidate set of one and makes itself the Designated Forwarder, so
    # both advertise P=1.
    When I apply config "z1-split.yaml" to namespace "z1"
    And I apply config "z2-split.yaml" to namespace "z2"
    Then show command "show bgp evpn" in namespace "z3" should eventually contain "l2-attr:P:mtu0"
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should eventually contain "(conflict, incumbent kept)"
    # z3 keeps the PE it was already using. The lowest-address tie-break
    # would have moved the traffic to 192.168.0.1 for no benefit — that is
    # the difference this scenario exists to pin.
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should contain "primary 192.168.0.2"
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should not contain "primary 192.168.0.1"
    # Both claims are visible, so the operator can see WHICH PEs disagree.
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should contain "192.168.0.1: role P"
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should contain "192.168.0.2: role P"
    # (No generation assertion here for the reason given above; what
    # matters — that the forwarder did not move — is the `primary` pair of
    # assertions immediately above.)

  Scenario: Losing the incumbent advances the generation
    Given the test topology exists
    # The incumbent's access port fails: its ES routes come off the wire
    # (RFC 7432 §8.2 mass withdraw) and it leaves the group, so the
    # surviving claimant takes over and the forwarder genuinely moves.
    When I execute "ip link set host0 down" in namespace "z2"
    Then show command "show bgp evpn ethernet-segment" in namespace "z3" should eventually contain "primary 192.168.0.1"
    And show command "show bgp evpn ethernet-segment" in namespace "z3" should not contain "192.168.0.2: role"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
