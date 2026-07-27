@serial
@bgp_evpn_vpws_startup_delay
Feature: BGP EVPN startup-delay — hold a booting PE out of the DF election
  As a network operator
  I want a PE that has just joined an Ethernet Segment to stay out of that
  segment's Designated-Forwarder election for a configured number of
  seconds, so it does not elect itself DF against a candidate set BGP has
  not populated yet and start duplicating traffic the incumbent DF is
  already forwarding toward the CE.

  The hold works by withholding the segment's ES routes — the Type-4 and the
  per-ES A-D — not by deferring only the local election. Deferring locally
  would deadlock: the other PEs would still see our Type-4, still run the
  same deterministic election over the same candidate set, and could hand
  the DF role to a PE that is refusing to forward. Withholding the routes
  keeps the holding PE out of their candidate sets entirely, so the
  incumbent simply keeps forwarding. On the holding PE's own VPWS services
  the hold forces the RFC 8214 §5 role to non-designated, so the remote PE
  does not use it either.

  Control-plane only: no cradle dataplane is attached, so this asserts the
  routes on the wire, the Layer-2 Attributes P/B bits, and the state each PE
  reports.

  Test Topology — three iBGP (AS 65001) EVPN speakers on a shared transport
  bridge br0. z1 and z2 are dual-homed to one CE over Ethernet Segment es1
  and both advertise VPWS service instance 101; z3 is the single-homed
  remote end of the E-Line. Only z1 carries a startup-delay:
  ```
  ┌───────────────────────────────────────────────┐
  │                      br0                      │
  └────┬──────────────────┬──────────────────┬────┘
   ┌───┴───┐          ┌───┴───┐          ┌───┴───┐
   │  z1   │          │  z2   │          │  z3   │  eline1: evi 100
   │ .0.1  │          │ .0.2  │          │ .0.3  │  z1,z2 svc-id 101
   │ LOC1  │          │ LOC2  │          │ LOC3  │  z3    svc-id 103
   │ hold  │          │  DF   │          └───────┘
   │  50s  │          │       │
   └───┬───┘          └───┬───┘
       └─── ES es1 ───────┘   single-active
       00:11:22:33:44:55:66:77:88:99
  ```
  With z1 holding, es1 has one candidate — z2 — and instance 101 carves to
  ordinal 101 % 1 = 0, so z2 forwards alone. When the hold elapses the list
  becomes [.0.1, .0.2] and instance 101 carves to ordinal 101 % 2 = 1: z2
  keeps the DF role and z1 becomes its backup. The DF deliberately does not
  move when z1 joins, so a role that flips to `backup` can only have come
  from z1 rejoining the election.

  Scenario: Setup topology, one holding PE and one incumbent on a shared segment
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
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z1" to "192.168.0.3" should be "Established"
    And BGP session in "z2" to "192.168.0.3" should be "Established"

  Scenario: The holding PE withholds its ES routes and stands its service down
    Given the test topology exists
    # z1 reports the hold and why the two facts below look the way they do.
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should contain "Startup hold:"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should contain "(ES routes suppressed)"
    # z1 counts only z2 on the segment — its own Type-4 is not originated,
    # so it is absent from its own candidate list as well as from z2's.
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should contain "Member VTEPs (1)"
    # The peer's view is the one that matters: z2 never learns z1 is on es1,
    # so its election cannot hand z1 a role z1 would refuse to honour.
    And show command "show bgp evpn" in namespace "z2" should not contain "[4]:[00:11:22:33:44:55:66:77:88:99]:[32]:[192.168.0.1]"
    # z1 keeps advertising the per-EVI Type-1 — the remote still learns its
    # SID and MTU — but with neither the P nor the B bit, so it is not used.
    And show command "show bgp evpn vpws" in namespace "z1" should contain "Role: non-designated"
    And show command "show bgp evpn" in namespace "z3" should eventually contain "l2-attr::mtu0"

  Scenario: The incumbent keeps forwarding for the whole hold
    Given the test topology exists
    # z2 is the sole candidate on es1, so it carries instance 101 alone —
    # the outcome the hold exists to protect.
    Then show command "show bgp evpn vpws" in namespace "z2" should contain "Role: primary (DF 192.168.0.2)"
    # And the remote end binds z2, not the PE that is standing down.
    And show command "show bgp evpn vpws" in namespace "z3" should eventually contain "Remote SID: fcbb:bbbb:2:"
    And show command "show bgp evpn vpws" in namespace "z3" should contain "(via 192.168.0.2)"
    And show command "show bgp evpn vpws" in namespace "z3" should contain "State: up"

  Scenario: The hold elapses and the PE joins the election
    Given the test topology exists
    # Waits out the remainder of the 50s hold within the polling budget. z1's
    # Type-4 comes back, so both PEs see two candidates.
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "Member VTEPs (2)"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "[4]:[00:11:22:33:44:55:66:77:88:99]:[32]:[192.168.0.1]"
    # The election re-runs on both PEs: instance 101 carves to z2, which was
    # already forwarding, and z1 takes the backup role it should have had all
    # along. No config changed — only the timer fired.
    And show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: backup (DF 192.168.0.2)"
    And show command "show bgp evpn vpws" in namespace "z2" should eventually contain "Role: primary (DF 192.168.0.2)"
    # z1's B bit reaches the wire, so z3 now has somewhere to fail over to.
    And show command "show bgp evpn" in namespace "z3" should eventually contain "l2-attr:B:mtu0"
    # The delay stays visible after it has run, so the operator can tell a
    # segment that was held from one that never had a delay configured.
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should contain "Startup delay: 50s (elapsed)"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should not contain "Startup hold:"

  Scenario: Re-configuring the delay re-arms the hold; clearing it ends the hold at once
    Given the test topology exists
    # Setting a delay on a live segment holds it again — asking for a hold
    # gets you one. 300s here, far longer than this scenario will wait.
    When I apply config "z1-rearm.yaml" to namespace "z1"
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "Startup hold:"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "Member VTEPs (1)"
    And show command "show bgp evpn" in namespace "z2" should eventually not contain "[4]:[00:11:22:33:44:55:66:77:88:99]:[32]:[192.168.0.1]"
    And show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: non-designated"
    # Clearing the leaf releases the hold immediately rather than leaving the
    # operator to wait out a timer they have just cancelled — the escape
    # hatch. Five minutes were left on the clock, so a segment that rejoins
    # here can only have been released by the delete.
    When I apply config "z1-nodelay.yaml" to namespace "z1"
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "Member VTEPs (2)"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should not contain "Startup hold:"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should not contain "Startup delay:"
    And show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: backup (DF 192.168.0.2)"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
