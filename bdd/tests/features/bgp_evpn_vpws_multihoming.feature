@serial
@bgp_evpn_vpws_multihoming
Feature: BGP EVPN VPWS multihoming — ESI and DF-elected P/B (RFC 8214 §5)
  As a network operator
  I want a VPWS service whose attachment circuit sits on a multihomed
  Ethernet Segment to advertise its Type-1 under that segment's ESI, and to
  elect its primary/backup role per <ESI, VPWS service instance> across the
  PEs advertising the segment's Type-4, so the remote PE learns which of the
  two attached PEs to use — and learns it again, without any config change,
  when one of them leaves the segment.

  Control-plane only: no cradle dataplane is attached, so this asserts the
  Type-1 ESI, the Layer-2 Attributes P/B bits on the wire, and the role each
  PE reports. Which SID the remote *binds* from a multihomed pair is remote
  selection, a separate phase — z3 here still binds a single end.

  Test Topology — three iBGP (AS 65001) EVPN speakers on a shared transport
  bridge br0. z1 and z2 are dual-homed to one CE over Ethernet Segment es1
  and both advertise VPWS service instance 101; z3 is the single-homed
  remote end of the E-Line:
  ```
  ┌───────────────────────────────────────────────┐
  │                      br0                      │
  └────┬──────────────────┬──────────────────┬────┘
   ┌───┴───┐          ┌───┴───┐          ┌───┴───┐
   │  z1   │          │  z2   │          │  z3   │  eline1: evi 100
   │ .0.1  │          │ .0.2  │          │ .0.3  │  z1,z2 svc-id 101
   │ LOC1  │          │ LOC2  │          │ LOC3  │  z3    svc-id 103
   └───┬───┘          └───┬───┘          └───────┘
       └─── ES es1 ───────┘   single-active
       00:11:22:33:44:55:66:77:88:99
  ```
  Instance 101 carves to ordinal 101 % 2 = 1 of the ascending VTEP list
  [.0.1, .0.2], so z2 is the DF (primary) and z1 its backup — the lower
  address deliberately is *not* the DF, which is what proves the carving
  keys on the service instance id rather than just picking the lowest PE.

  Scenario: Setup topology, two PEs on one Ethernet Segment plus a remote PE
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

  Scenario: Both attached PEs originate the Type-1 under the segment's ESI
    Given the test topology exists
    # z3 sees service instance 101 advertised under es1's ESI, not the
    # all-zero one a single-homed service would carry.
    Then show command "show bgp evpn" in namespace "z3" should eventually contain "[1]:[00:11:22:33:44:55:66:77:88:99]:[101]"
    # z3's own Type-1 stays single-homed: all-zero ESI, instance 103.
    And show command "show bgp evpn" in namespace "z3" should contain "[1]:[00:00:00:00:00:00:00:00:00:00]:[103]"
    # Both attached PEs also appear on the segment itself (Type-4 exchange),
    # which is what gives the election two candidates.
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "Member VTEPs (2)"

  Scenario: Single-active carving elects one primary and one backup
    Given the test topology exists
    # Instance 101 -> ordinal 1 -> z2 is DF. Both PEs agree on the winner.
    Then show command "show bgp evpn vpws" in namespace "z2" should eventually contain "Role: primary (DF 192.168.0.2)"
    And show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: backup (DF 192.168.0.2)"
    # Neither PE names a segment on its vpws service: es1 declares ce1 as its
    # access port and the service's AC is ce1, so the binding is inferred —
    # `(from ce1)` is the show reporting that it was derived, not configured.
    And show command "show bgp evpn vpws" in namespace "z1" should contain "Ethernet Segment: es1 (from ce1) (ESI 00:11:22:33:44:55:66:77:88:99, single-active)"
    # The election reaches the wire: z3 receives one P and one B for the
    # same service instance.
    And show command "show bgp evpn" in namespace "z3" should eventually contain "l2-attr:P:mtu0"
    And show command "show bgp evpn" in namespace "z3" should eventually contain "l2-attr:B:mtu0"

  Scenario: All-active makes every attached PE primary
    Given the test topology exists
    When I apply config "z1-allactive.yaml" to namespace "z1"
    And I apply config "z2-allactive.yaml" to namespace "z2"
    # RFC 8214 §5: under all-active both PEs forward, so both advertise P=1
    # and the backup bit disappears from the segment entirely.
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: primary"
    And show command "show bgp evpn vpws" in namespace "z2" should eventually contain "Role: primary"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "(from ce1) (ESI 00:11:22:33:44:55:66:77:88:99, all-active)"
    And show command "show bgp evpn" in namespace "z3" should eventually not contain "l2-attr:B:mtu0"
    # Back to single-active for the re-election scenario below.
    When I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: backup (DF 192.168.0.2)"

  Scenario: A PE leaving the segment re-elects the survivor with no config change on it
    Given the test topology exists
    # z2 drops out of es1: its Type-4 is withdrawn, so z1's candidate set
    # shrinks to itself and instance 101 re-carves onto z1. Nothing about
    # z1's own config changed — this is the receive-path DF re-election.
    When I apply config "z2-noes.yaml" to namespace "z2"
    Then show command "show bgp evpn" in namespace "z1" should eventually not contain "[4]:[00:11:22:33:44:55:66:77:88:99]:[32]:[192.168.0.2]"
    And show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: primary (DF 192.168.0.1)"
    # z1 now advertises P; no backup is left on the segment.
    And show command "show bgp evpn" in namespace "z3" should eventually not contain "l2-attr:B:mtu0"
    # z2's service falls back to single-homed: all-zero ESI, primary.
    And show command "show bgp evpn vpws" in namespace "z2" should eventually not contain "Ethernet Segment:"
    # Put z2 back on the segment: z1 hands the DF role back, again with no
    # config change of its own.
    When I apply config "z2-1.yaml" to namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: backup (DF 192.168.0.2)"

  Scenario: An AC claimed by two segments is reported, not guessed; the leaf resolves it
    Given the test topology exists
    # Add a second segment es2 that also claims ce1. Inference now has two
    # candidates and refuses both — picking one would silently move the
    # service onto the wrong ESI.
    When I apply config "z1-ambiguous.yaml" to namespace "z1"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Ethernet Segment: ambiguous"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "es1, es2 claim ce1"
    # Ambiguous is not a segment: the service falls back to single-homed, so
    # its Type-1 re-keys onto the all-zero ESI.
    And show command "show bgp evpn" in namespace "z3" should eventually contain "[1]:[00:00:00:00:00:00:00:00:00:00]:[101]"
    And show command "show bgp evpn vpws" in namespace "z1" should not contain "Role:"
    # Naming one on the leaf is the documented way out. es2 wins over the
    # inference that would have picked neither, and the Type-1 re-keys again
    # — now onto es2's ESI, where z1 is the only PE and so elects itself.
    When I apply config "z1-override.yaml" to namespace "z1"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Ethernet Segment: es2 (ESI 00:aa:bb:cc:dd:ee:ff:01:02:03, single-active)"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "Role: primary (DF 192.168.0.1)"
    # An overridden binding is not annotated `(from ...)` — it was configured.
    And show command "show bgp evpn vpws" in namespace "z1" should not contain "es2 (from ce1)"
    And show command "show bgp evpn" in namespace "z3" should eventually contain "[1]:[00:aa:bb:cc:dd:ee:ff:01:02:03]:[101]"
    # Back to the inferred single-segment config for the scenarios that follow.
    When I apply config "z1-1.yaml" to namespace "z1"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: backup (DF 192.168.0.2)"

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
