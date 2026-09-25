@serial
@bgp_evpn_single_active
Feature: EVPN single-active — the elected role on the per-EVI Ethernet A-D
  As a network operator running a single-active Ethernet Segment
  I want each PE to advertise its elected role in the Layer-2 Attributes
  extended community of its per-EVI Ethernet A-D (draft-ietf-bess-rfc7432bis
  §7.11.1), so a remote ingress PE is TOLD which PE forwards the segment's
  known unicast instead of inferring it from which PE happened to advertise
  the MACs — and so a Designated-Forwarder change re-points that traffic with
  an attribute update rather than a MAC relearn.

  RFC 7432 leaves this gap open: the DF election is local to the segment's
  PEs and nothing on the wire carries its outcome. zebra-rs's pre-existing
  answer is inference (`Bgp::es_sa_primary` counts each PE's Type-2s), which
  has nothing to read before the CE has sourced a frame and follows a DF
  change only as MACs are relearned. `role-signaling l2-attr` replaces the
  guess with a signal. Consuming it on the receiving side — the remote's
  forwarding group — is the next slice; what is proven here is that the
  correct bits are originated, that they move with the election, and that
  they are absent unless asked for.

  Test Topology — two PEs on a shared transport bridge, each with a bridge
  domain for VNI 10 and a CE-facing access port on the SAME segment es1:
  ```
  ┌─────────────────────────────────┐
  │               br0               │
  └───────┬─────────────────┬───────┘
     ┌────┴────┐       ┌────┴────┐
     │   z1    │       │   z2    │  both: ethernet-segment es1 (single-active)
     │ .0.1/24 │       │ .0.2/24 │        esi 00:11:..:99, interface host0
     │ pref 200│       │ pref 100│        role-signaling l2-attr
     │ br10 +  │       │ br10 +  │        vxlan10 (VNI 10) + host0
     │ vxlan10 │       │ vxlan10 │
     └─────────┘       └─────────┘
  ```
  RFC 9785 preference pins the DF, so every assertion below is a property of
  the configuration rather than of a hash: z1 (pref 200) is the DF and z2
  (pref 100) its backup, which is also what service carving would give for
  VNI 10 — until the preference is raised on z2, which carving never would.

  Scenario: Setup topology, EVPN session and both bridge domains
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    # Each PE gets a learning bridge for VNI 10 plus the access port named by
    # the segment. host0 is created AFTER the config names it, so the ES
    # binding starts unresolvable and has to catch up on the LinkAdd event —
    # the per-EVI A-D only exists once the port's bridge ties it to a VNI.
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

  Scenario: The Designated Forwarder advertises P and its backup advertises B
    Given the test topology exists
    # Preference-based election (RFC 9785 Alg 2) makes z1 the DF for every
    # bridge domain on the segment, so z1's per-EVI A-D carries P=1/B=0 and
    # z2's — the election's runner-up — carries P=0/B=1.
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "[1]:[00:11:22:33:44:55:66:77:88:99]:[0]"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "l2-attr:P:mtu0"
    And show command "show bgp evpn" in namespace "z1" should eventually contain "l2-attr:B:mtu0"
    # Each PE says the same thing about itself locally.
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "Role signaling: l2-attr (per-EVI A-D P/B)"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "bd 10: primary"
    And show command "show bgp evpn ethernet-segment" in namespace "z2" should eventually contain "bd 10: backup"
    # ... and it is the same election the BUM filter uses.
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should contain "Designated Forwarder (tag 0): 192.168.0.1 (this node)"

  Scenario: A DF change moves the bits without withdrawing the route
    Given the test topology exists
    # Raise z2's preference above z1's. The election flips to z2 — which
    # service carving would NOT do for VNI 10 — and both PEs restate their
    # role on the route they are already advertising.
    When I apply config "z2-pref300.yaml" to namespace "z2"
    Then show command "show bgp evpn ethernet-segment" in namespace "z2" should eventually contain "bd 10: primary"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "bd 10: backup"
    # On the wire the bits swap: z1 now advertises B, z2 advertises P.
    And show command "show bgp evpn" in namespace "z2" should eventually contain "l2-attr:B:mtu0"
    And show command "show bgp evpn" in namespace "z1" should eventually contain "l2-attr:P:mtu0"
    # The route itself never went away — the remote re-points on an
    # attribute update, which is the entire point of signalling the role
    # rather than suppressing the advertisement. (An assertion on the NLRI
    # still being present is a proxy: it would not catch a withdraw followed
    # by a re-announce inside one poll interval.)
    And show command "show bgp evpn" in namespace "z2" should contain "[1]:[00:11:22:33:44:55:66:77:88:99]:[0]"
    And show command "show bgp evpn" in namespace "z1" should contain "[1]:[00:11:22:33:44:55:66:77:88:99]:[0]"

  Scenario: Without role-signaling the A-D carries no L2-Attributes at all
    Given the test topology exists
    # The negative control. z1 keeps its ESI, its port, its preference and
    # its single-active mode; only `role-signaling` goes back to the default.
    # Its per-EVI A-D must lose the EC while remaining advertised.
    When I apply config "z1-inferred.yaml" to namespace "z1"
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually not contain "Role signaling:"
    # z1 is the backup at this point (z2 raised its preference above z1's in
    # the scenario before), so its bit is the one that must vanish from z2's
    # table. z2 still signals its own P — naming the specific bits is what
    # makes this a control rather than a blanket "no EC anywhere" assertion
    # that would also pass if the feature simply stopped working.
    And show command "show bgp evpn" in namespace "z2" should eventually not contain "l2-attr:B:mtu0"
    And show command "show bgp evpn" in namespace "z2" should contain "l2-attr:P:mtu0"
    And show command "show bgp evpn" in namespace "z2" should contain "[1]:[00:11:22:33:44:55:66:77:88:99]:[0]"

  Scenario: A redundancy-mode edit re-tees the datapath gate on its own
    Given the test topology exists
    # The mode is not only a wire attribute: it is what the datapath gate is
    # made of. A single-active non-DF blocks its access port in BOTH
    # directions; an all-active one only filters BUM. Both must follow a
    # config edit immediately — with no incoming BGP update to trigger a
    # drain — or the PE forwards under one mode while advertising the other.
    # z1 is the non-DF here (z2 raised its preference two scenarios ago), so
    # it is exactly the PE whose port the gate is holding down.
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "bd 10: non-DF, single-active"
    # all-active: the gate must stop blocking, and the role signal must go
    # with it (all-active PEs all forward, so P/B would be a lie).
    When I apply config "z1-allactive.yaml" to namespace "z1"
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "bd 10: non-DF, all-active"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should not contain "bd 10: non-DF, single-active"
    And show command "show bgp evpn" in namespace "z2" should eventually not contain "l2-attr:B:mtu0"
    # ... and back, which is the transition that would otherwise leave the
    # port forwarding while we advertise Backup.
    When I apply config "z1-1.yaml" to namespace "z1"
    Then show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "bd 10: non-DF, single-active"
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should not contain "bd 10: non-DF, all-active"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "l2-attr:B:mtu0"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
