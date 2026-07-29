@serial
@bgp_evpn_srv6_macip_multihoming
Feature: EVPN Type-2 multihoming signals over SRv6 — ESI on the MAC route
  As a network operator multihoming a CE to two EVPN-over-SRv6 PEs
  I want a MAC learned on an Ethernet Segment's access port to advertise
  its Type-2 under the segment ESI (RFC 7432 §7.1), alongside both PEs'
  per-ES Type-1 A-D and Type-4 routes, so a receiver holds the complete
  input set for §8.4 aliasing and §8.2 mass withdraw.

  Scope is the SIGNAL set, not its consumption: zebra-rs originates the
  full input set — Type-2 under the ESI, per-ES A-D, per-EVI A-D, Type-4
  — but does not yet alias MAC traffic across the segment's PEs nor
  mass-withdraw MACs on a per-ES A-D loss (both exist for VPWS only —
  `vpws_gather_remotes` gates on per-ES A-D liveness; the MAC install
  path does not, and `MacEntry` only recently grew room for a second
  destination). What is proven here is that every route a consumer would
  need is originated, exchanged and revoked correctly under
  `encapsulation srv6`.

  The ES machinery itself (Type-4/ES-Import RT, membership, DF election)
  is covered by bgp_evpn_es under the default encapsulation with no MACs;
  single-PE runtime ESI bind/unbind by bgp_evpn_srv6_macip. This
  feature is the two-PE composition: a segment shared by both PEs, bound
  on z1 to an access port in the STARTUP config (the binding resolves via
  the RibRx::LinkAdd replay — host0 is created only after the config
  lands), and a CE MAC learned there. z2 configures the segment's ESI
  but binds no port: its Type-4 and per-ES A-D need none, and a bound
  port's own auto-generated MAC would originate an ESI-carrying Type-2
  from z2 that never transitions, defeating whole-output assertions on
  z1's bind/unbind. (Note z1's host0 own MAC is bridge-learned and
  advertised too — every z1 Type-2 sheds the ESI together on unbind.)

  ```
   z1 [br10: vxlan10 + host0]  ══════  z2 [br10: vxlan10]
      LOC1 fcbb:bbbb:1::/48   2001:db8:12::/64   LOC2 fcbb:bbbb:2::/48
      router-id 192.168.0.1                      router-id 192.168.0.2
      both: ethernet-segment es1, esi 00:11:..:99 (z1: interface host0)
      CE MAC aa:bb:cc:dd:ee:01 parked on z1's host0
  ```

  Config files (in `bdd/tests/configs/bgp_evpn_srv6_macip_multihoming/`):
  - z1.yaml, z2.yaml — `advertise-all-vni` + `encapsulation srv6`, a
    locator each, the shared `ethernet-segment es1` (bound to `host0`
    on z1 only), and the EVPN AFI/SAFI as the only negotiated family.

  Scenario: Setup topology and the EVPN session over SRv6
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1z2" to namespace "z2" interface "z2z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    # Each PE gets a learning bridge for VNI 10; z1 also gets the host0
    # access port. host0 is created AFTER the config named it as es1's
    # interface, so the ES binding starts unresolvable and must catch up
    # on the LinkAdd event.
    And I execute "ip link add br10 type bridge" in namespace "z1"
    And I execute "ip link set vxlan10 master br10" in namespace "z1"
    And I execute "ip link set br10 up" in namespace "z1"
    And I execute "ip link add host0 type dummy" in namespace "z1"
    And I execute "ip link set host0 master br10" in namespace "z1"
    And I execute "ip link set host0 up" in namespace "z1"
    And I execute "ip link add br10 type bridge" in namespace "z2"
    And I execute "ip link set vxlan10 master br10" in namespace "z2"
    And I execute "ip link set br10 up" in namespace "z2"
    And I wait 12 seconds for BGP to operate
    Then BGP session in "z1" to "2001:db8:12::2" should be "Established"
    And BGP session in "z2" to "2001:db8:12::1" should be "Established"

  Scenario: Both PEs discover each other on the segment under SRv6 encapsulation
    Given the test topology exists
    # z1 imports z2's Type-4 — the ES routes are encapsulation-independent
    # and must flow unchanged with `encapsulation srv6` configured.
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "[4]:[00:11:22:33:44:55:66:77:88:99]:[32]:[192.168.0.2]"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "[4]:[00:11:22:33:44:55:66:77:88:99]:[32]:[192.168.0.1]"
    # The per-ES A-D (mass-withdraw carrier) with the all-active ESI Label EC.
    And show command "show bgp evpn" in namespace "z2" should eventually contain "[1]:[00:11:22:33:44:55:66:77:88:99]:[4294967295]"
    And show command "show bgp evpn" in namespace "z2" should contain "esi-label:all-active:0"
    # The per-EVI A-D (Ethernet Tag 0 — one bridge domain per VNI), which is
    # the route that makes aliasing possible at all: it says "this PE can
    # reach MACs on this segment in this EVI" WITHOUT having learned any of
    # them. Its EVI membership is resolved from the access port's bridge, so
    # its presence also proves host0 was tied to vxlan10's VNI.
    And show command "show bgp evpn" in namespace "z2" should eventually contain "[1]:[00:11:22:33:44:55:66:77:88:99]:[0]"
    # Membership agrees on both nodes; the usual 2-PE service carving elects
    # the lower VTEP (z1) as DF for tag 0.
    And show command "show bgp evpn ethernet-segment" in namespace "z1" should eventually contain "Member VTEPs (2)"
    And show command "show bgp evpn ethernet-segment" in namespace "z2" should eventually contain "Designated Forwarder (tag 0): 192.168.0.1"

  Scenario: A MAC on one attached PE advertises under the segment ESI
    Given the test topology exists
    # The CE MAC appears on z1's access port only. Its Type-2 must carry
    # es1's ESI — the startup-config binding resolved via LinkAdd, since
    # host0 postdates the config — and the per-VNI End.DT2U SID as usual.
    When I execute "bridge fdb add aa:bb:cc:dd:ee:01 dev host0 master static" in namespace "z1"
    Then show command "show bgp evpn" in namespace "z1" should eventually contain "ESI: 00:11:22:33:44:55:66:77:88:99"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "aa:bb:cc:dd:ee:01"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "ESI: 00:11:22:33:44:55:66:77:88:99"
    And show command "show bgp evpn" in namespace "z2" should contain "(End.DT2U)"
    # z2 now holds the complete RFC 7432 §8.4 aliasing input set: the MAC
    # under a non-zero ESI, plus a live per-ES A-D for that ESI from z1 —
    # and z2 is itself attached to the segment.
    And show command "show bgp evpn" in namespace "z2" should contain "[1]:[00:11:22:33:44:55:66:77:88:99]:[4294967295]"

  Scenario: Unbinding the access port returns the MAC to single-homed
    Given the test topology exists
    # Only the port binding goes; the segment stays configured, so the ES
    # routes (Type-4, per-ES A-D) must survive while the Type-2 sheds its
    # ESI — this isolates the §7.1 MAC binding from the ES lifecycle.
    When I apply command "delete router bgp afi-safi evpn ethernet-segment es1 interface host0" in namespace "z1"
    Then show command "show bgp evpn" in namespace "z2" should eventually not contain "ESI: 00:11:22:33:44:55:66:77:88:99"
    And show command "show bgp evpn" in namespace "z2" should contain "aa:bb:cc:dd:ee:01"
    And show command "show bgp evpn" in namespace "z2" should contain "[4]:[00:11:22:33:44:55:66:77:88:99]:[32]:[192.168.0.1]"
    # Re-binding restores the multihomed advertisement in place.
    When I apply command "set router bgp afi-safi evpn ethernet-segment es1 interface host0" in namespace "z1"
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "ESI: 00:11:22:33:44:55:66:77:88:99"

  Scenario: Deleting the segment revokes the mass-withdraw signal set
    Given the test topology exists
    # Removing es1 on z1 is the §8.2 trigger a consumer would react to:
    # z1's Type-4 and per-ES A-D are withdrawn, membership shrinks to z2
    # alone, and the MAC re-originates single-homed — but the Type-2
    # itself survives, because the MAC is still a local host on z1.
    When I apply command "delete router bgp afi-safi evpn ethernet-segment es1" in namespace "z1"
    Then show command "show bgp evpn" in namespace "z2" should eventually not contain "[4]:[00:11:22:33:44:55:66:77:88:99]:[32]:[192.168.0.1]"
    # The per-EVI A-D goes with it. It has to be revoked from the segment
    # teardown rather than from port reconciliation: once es1 is gone nothing
    # associates the ESI with a port any more, so a port-driven pass could no
    # longer tell the route had ever been ours, and it would linger forever.
    And show command "show bgp evpn" in namespace "z2" should eventually not contain "[1]:[00:11:22:33:44:55:66:77:88:99]:[0]"
    And show command "show bgp evpn" in namespace "z2" should eventually not contain "ESI: 00:11:22:33:44:55:66:77:88:99"
    And show command "show bgp evpn ethernet-segment" in namespace "z2" should eventually contain "Member VTEPs (1)"
    And show command "show bgp evpn" in namespace "z2" should contain "aa:bb:cc:dd:ee:01"
    And show command "show bgp evpn" in namespace "z2" should contain "(End.DT2U)"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
