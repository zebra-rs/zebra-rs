@serial
@bgp_evpn_etree
Feature: EVPN E-Tree leaf ACs: roles in the data plane, Type-2 colouring (RFC 8317)
  As a network operator running an EVPN E-Tree
  I want each leaf attachment circuit's role programmed into the cradle
  data plane, so a leaf never reaches another leaf on the same PE, and a
  MAC learned on a leaf AC advertised with the E-Tree community's
  Leaf-Indication flag, so a receiving PE carries that flag into its own
  data plane FDB.

  `router bgp afi-safi evpn etree` is always available (the `etree`
  feature no longer gates it, so the daemons start without it), and a
  leaf AC needs the cradle data plane: the kernel bridge cannot keep
  leaves apart, so a commit naming one without `system ebpf` (or
  `system cradle`) is refused. zebra-rs's engine supervisor sends each
  role (`SetEtreeRole`) before it attaches the port, and again to a
  respawned engine before re-attaching its ports.

  Known unicast from a leaf toward a flagged MAC on another PE is dropped
  by that PE's engine before encapsulation; cradle-rs proves that drop
  over a zebra-rs-driven VXLAN fabric. This feature stops at the flag
  reaching z2's engine FDB.

  ```
   h1 (leaf) ─ l1 ┐
   h2 (leaf) ─ l2 ├ z1 [br10: vxlan10] ── br0 ── z2 [br10: vxlan10] ─ r2 ─ h4
   h3 (root) ─ r1 ┘   192.168.0.1               192.168.0.2
   hosts 10.10.0.0/24, VNI 10 -> RD <router-id>:10, RT 65001:10
  ```

  Config files (in `bdd/tests/configs/bgp_evpn_etree/`):
  - z1.yaml — EVPN/VXLAN, no `system ebpf` yet.
  - z1-etree.yaml — z1 with the managed engine, its ports, and l1 and l2
    as leaf ACs.
  - z2.yaml — a root-only PE with the managed engine.

  Scenario: Setup topology and the EVPN session
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "h1"
    And I create namespace "h2"
    And I create namespace "h3"
    And I create namespace "h4"
    And I connect namespace "z1" interface "l1" to namespace "h1" interface "eth0"
    And I connect namespace "z1" interface "l2" to namespace "h2" interface "eth0"
    And I connect namespace "z1" interface "r1" to namespace "h3" interface "eth0"
    And I connect namespace "z2" interface "r2" to namespace "h4" interface "eth0"
    # No IPv6 on the hosts: an idle host keeps sending router
    # solicitations, and each one makes cradle re-report its MAC, which
    # re-advertises it. The colour change in the last scenario must come
    # from the config change alone.
    And I execute "sysctl -w net.ipv6.conf.all.disable_ipv6=1" in namespace "h1"
    And I execute "sysctl -w net.ipv6.conf.all.disable_ipv6=1" in namespace "h2"
    And I execute "sysctl -w net.ipv6.conf.all.disable_ipv6=1" in namespace "h3"
    And I execute "sysctl -w net.ipv6.conf.all.disable_ipv6=1" in namespace "h4"
    And I execute "ip link set eth0 address 02:00:00:00:e1:01" in namespace "h1"
    And I execute "ip link set eth0 address 02:00:00:00:e1:02" in namespace "h2"
    And I execute "ip link set eth0 address 02:00:00:00:e1:03" in namespace "h3"
    And I execute "ip link set eth0 address 02:00:00:00:e2:04" in namespace "h4"
    And I add address "10.10.0.1/24" to interface "eth0" in namespace "h1"
    And I add address "10.10.0.2/24" to interface "eth0" in namespace "h2"
    And I add address "10.10.0.3/24" to interface "eth0" in namespace "h3"
    And I add address "10.10.0.4/24" to interface "eth0" in namespace "h4"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    # br10 carries VNI 10 on each PE, with the access ports in it.
    And I execute "ip link add br10 type bridge" in namespace "z1"
    And I execute "ip link set vxlan10 master br10" in namespace "z1"
    And I execute "ip link set l1 master br10" in namespace "z1"
    And I execute "ip link set l2 master br10" in namespace "z1"
    And I execute "ip link set r1 master br10" in namespace "z1"
    And I execute "ip link set br10 up" in namespace "z1"
    And I execute "ip link add br10 type bridge" in namespace "z2"
    And I execute "ip link set vxlan10 master br10" in namespace "z2"
    And I execute "ip link set r2 master br10" in namespace "z2"
    And I execute "ip link set br10 up" in namespace "z2"
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Established"
    And BGP session in "z2" to "192.168.0.1" should eventually be "Established"

  Scenario: A leaf AC is refused without the cradle data plane
    Given the test topology exists
    Then applying command "set router bgp afi-safi evpn etree leaf-interface l1" in namespace "z1" should be rejected with "E-Tree needs the cradle data plane"
    And show command "show running-config" in namespace "z1" should not contain "etree"

  Scenario: With the engine on, the leaf roles are programmed and the ports attached
    Given the test topology exists
    When I apply config "z1-etree.yaml" to namespace "z1"
    Then show command "show running-config" in namespace "z1" should contain "leaf-interface l1"
    # Each role reaches the engine before its port; until then the line
    # reads `l1 (pending)` and the port row `held`.
    And show command "show ebpf" in namespace "z1" should eventually contain "E-Tree leaves:   l1, l2"
    And show command "show ebpf" in namespace "z1" should eventually not contain "(pending)"
    And show command "show ebpf" in namespace "z1" should eventually contain "3 attached"
    And show command "show ebpf" in namespace "z1" should not contain "held"

  Scenario: A leaf reaches the root on its PE but not the other leaf
    Given the test topology exists
    Then ping from "h1" to "10.10.0.3" should eventually succeed
    And ping from "h2" to "10.10.0.3" should eventually succeed
    And ping from "h1" to "10.10.0.2" should fail
    # The engine dropped it as leaf to leaf, not for some other reason.
    And show command "show ebpf stats" in namespace "z1" should not contain "l2_drop_etree_local 0"

  Scenario: Only the MACs learned on leaf ACs are advertised as leaves
    Given the test topology exists
    # The engine learned h1, h2 and h3 above. Two of them are leaves.
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "02:00:00:00:e1:03"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "etree:leaf"
    And show command "show bgp evpn etree" in namespace "z2" should eventually contain "EVI 10         2"
    And show command "show bgp evpn etree" in namespace "z1" should contain "local MACs 1"
    # The flag reached z2's data plane FDB (`FdbRemote.etree_leaf`).
    And show command "show ebpf l2" in namespace "z2" should eventually contain "etree-leaf"

  Scenario: A respawned engine gets the roles back before the ports
    Given the test topology exists
    When I kill the cradle engine in namespace "z1"
    Then show command "show ebpf" in namespace "z1" should eventually contain "Engine restarts: 1"
    # Roles and ports are re-applied in the same reconcile that saw the
    # engine come back, roles first.
    And show command "show ebpf" in namespace "z1" should contain "E-Tree leaves:   l1, l2"
    And show command "show ebpf" in namespace "z1" should not contain "(pending)"
    And show command "show ebpf" in namespace "z1" should eventually contain "3 attached"
    And ping from "h1" to "10.10.0.3" should eventually succeed
    And ping from "h1" to "10.10.0.2" should fail
    # Counters start over with the new engine: this drop is its own.
    And show command "show ebpf stats" in namespace "z1" should not contain "l2_drop_etree_local 0"

  Scenario: A leaf AC turned into a root reaches the other leaf and loses its colour
    Given the test topology exists
    # Let the engine restart above settle first: zebra-rs resubscribes to
    # the new engine's MAC learning a couple of seconds after it comes up,
    # and the replay re-advertises the local MACs. Landing after the change
    # below, it would recolour h2's MAC by itself and hide a missing
    # re-advertisement on the config path.
    When I wait 10 seconds
    Then show command "show bgp evpn etree" in namespace "z2" should contain "EVI 10         2"
    When I apply command "delete router bgp afi-safi evpn etree leaf-interface l2" in namespace "z1"
    # The config change alone re-advertises h2's MAC without the flag: one
    # leaf MAC is left. Checked before any traffic from h2, whose re-learn
    # would re-advertise it too (and h2 is silent: no IPv6).
    Then show command "show bgp evpn etree" in namespace "z2" should eventually contain "EVI 10         1"
    And show command "show bgp evpn" in namespace "z2" should contain "02:00:00:00:e1:02"
    And show command "show ebpf" in namespace "z1" should eventually contain "E-Tree leaves:   l1"
    And show command "show ebpf" in namespace "z1" should not contain "l1, l2"
    And ping from "h1" to "10.10.0.2" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "h1"
    And I delete namespace "h2"
    And I delete namespace "h3"
    And I delete namespace "h4"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
