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

  Scenario: Preference-based DF election overrides the carving ordinal
    Given the test topology exists
    # Switch es1 to Alg 2 with z1 bidding 300 and z2 bidding 100. Under
    # carving, instance 101 elected z2 (ordinal 101 % 2 = 1); preference is
    # per-segment, so the higher bid now wins every instance — the DF flips
    # to z1 with no change to the service ids.
    When I apply config "z1-pref.yaml" to namespace "z1"
    And I apply config "z2-pref.yaml" to namespace "z2"
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "DF algorithm: preference-based (local pref 300)"
    And show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: primary (DF 192.168.0.1)"
    And show command "show bgp evpn vpws" in namespace "z2" should eventually contain "Role: backup (DF 192.168.0.1)"
    # Each PE's bid rides its Type-4's DF Election EC, so the peer sees it.
    And show command "show bgp evpn" in namespace "z2" should eventually contain "df-election:alg2:pref300"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should contain "192.168.0.2 pref 100"
    # Raising z2 above z1 hands the DF back — the election is re-run from the
    # peer's Type-4 alone, with no config change on z1.
    When I apply config "z1-1.yaml" to namespace "z1"
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "DF algorithm: service-carving (default)"
    # One PE back on Alg 0 means the segment cannot agree, so RFC 8584
    # negotiation drops both to carving — and instance 101 carves to z2 again.
    And show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: backup (DF 192.168.0.2)"
    When I apply config "z2-1.yaml" to namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: backup (DF 192.168.0.2)"

  Scenario: The remote PE binds the primary of a multihomed pair
    Given the test topology exists
    # z1 and z2 both advertise service instance 101 under es1's ESI. Instance
    # 101 carves to z2, so z2 sends P=1 and z1 sends B=1 — z3 must bind z2's
    # SID (carved from LOC2), not simply the first route it happened to see.
    Then show command "show bgp evpn vpws" in namespace "z3" should eventually contain "Remote SID: fcbb:bbbb:2:"
    And show command "show bgp evpn vpws" in namespace "z3" should contain "(via 192.168.0.2)"
    # Both ends are visible to z3, and it knows one is standing by.
    And show command "show bgp evpn vpws" in namespace "z3" should contain "Remote endpoints: 2 (multihomed; 1 standing by)"
    And show command "show bgp evpn vpws" in namespace "z3" should contain "State: up"

  Scenario: Losing the primary fails the service over to the backup
    Given the test topology exists
    # Remove z2's service so it withdraws its per-EVI Type-1, leaving only
    # z1's B=1 route. Before remote selection this unbound the AC and the
    # E-Line went down; now it re-selects onto the backup.
    When I apply config "z2-novpws.yaml" to namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z3" should eventually contain "Remote SID: fcbb:bbbb:1:"
    And show command "show bgp evpn vpws" in namespace "z3" should contain "(via 192.168.0.1, backup)"
    # One endpoint left, so no standby line, and the service stays up.
    And show command "show bgp evpn vpws" in namespace "z3" should not contain "standing by"
    And show command "show bgp evpn vpws" in namespace "z3" should contain "State: up"
    # Restoring the primary takes the service back — the re-selection is
    # symmetric, and z3 changed no config in either direction.
    When I apply config "z2-1.yaml" to namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z3" should eventually contain "Remote SID: fcbb:bbbb:2:"
    And show command "show bgp evpn vpws" in namespace "z3" should contain "(via 192.168.0.2)"

  Scenario: AC-influenced DF election re-elects the service whose AC went down (RFC 8584 §4)
    Given the test topology exists
    # Real links this time. The segment port is a dummy ce1; the E-Line's
    # attachment circuit is the VLAN sub-interface ce1.100 on it, bound to
    # es1 explicitly. Taking the AC down then withdraws only the service's
    # Type-1 while the segment (Type-4, per-ES A-D) stays up — the case
    # AC-DF exists for. A segment *port* down is plain segment loss: the ES
    # routes are withheld and every PE re-elects without AC-DF.
    When I execute "ip link add ce1 type dummy" in namespace "z1"
    And I execute "ip link add link ce1 name ce1.100 type vlan id 100" in namespace "z1"
    And I execute "ip link set ce1 up" in namespace "z1"
    And I execute "ip link set ce1.100 up" in namespace "z1"
    And I execute "ip link add ce1 type dummy" in namespace "z2"
    And I execute "ip link add link ce1 name ce1.100 type vlan id 100" in namespace "z2"
    And I execute "ip link set ce1 up" in namespace "z2"
    And I execute "ip link set ce1.100 up" in namespace "z2"
    And I apply config "z1-acdf.yaml" to namespace "z1"
    And I apply config "z2-acdf.yaml" to namespace "z2"
    # Both Type-4s carry the capability, so it is in effect on the segment;
    # the election itself is unchanged while every AC is up.
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "df-election:alg0+ac-df"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "AC-DF: advertised, in effect (2 of 2 PEs advertise it)"
    And show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: backup (DF 192.168.0.2)"
    # z2's AC fails: its Type-1 is withdrawn, its Type-4 is not. Under
    # AC-DF z1's candidate list for instance 101 shrinks to itself, so z1
    # takes the primary role — with the segment still two members strong.
    When I execute "ip link set ce1.100 down" in namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: primary (DF 192.168.0.1)"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should contain "Member VTEPs (2)"
    And show command "show bgp evpn vpws" in namespace "z3" should eventually contain "(via 192.168.0.1)"
    # The AC returns: z2 re-originates and the carving picks it again.
    When I execute "ip link set ce1.100 up" in namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z1" should eventually contain "Role: backup (DF 192.168.0.2)"
    And show command "show bgp evpn vpws" in namespace "z3" should eventually contain "(via 192.168.0.2)"
    # Negative control: without the capability the same AC failure leaves
    # z1 a backup — z2 is still on the segment, so the carving still picks
    # it — and the remote end rides z1's B route instead.
    When I apply config "z1-acdf-off.yaml" to namespace "z1"
    And I apply config "z2-acdf-off.yaml" to namespace "z2"
    Then show command "show bgp evpn" in namespace "z1" should eventually not contain "+ac-df"
    When I execute "ip link set ce1.100 down" in namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z3" should eventually contain "(via 192.168.0.1, backup)"
    And show command "show bgp evpn vpws" in namespace "z1" should contain "Role: backup (DF 192.168.0.2)"
    When I execute "ip link set ce1.100 up" in namespace "z2"
    Then show command "show bgp evpn vpws" in namespace "z3" should eventually contain "(via 192.168.0.2)"

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
