@serial
@bgp_evpn_srv6_p2mp
Feature: BGP EVPN BUM over SRv6 P2MP replication (RFC 9524) — cradle engine
  As a network operator
  I want the BGP control plane to program EVPN BUM replication into the cradle
  eBPF engine: two SRv6 EVPN PEs exchange their End.DT2M SIDs over a Type-3
  IMET, and each daemon (with `system ebpf enabled`) tees the datapath to
  cradle — its own End.DT2M leaf SID into the SRv6 table, and each remote PE's
  End.DT2M SID as a VNI-10 replication slot.

  This proves the control-plane -> cradle-tee integration end to end (session,
  SID exchange, engine programming). BUM forwarding is the cradle engine's job
  (the retired standalone tc-evpn-replicate offload is superseded); its packet
  path is exercised by the veth scripts in cradle-rs
  (crates/tc-evpn-replicate/scripts/veth-*.sh). Requires /usr/bin/cradle — see
  the cradle_spawn feature header for install instructions.

  Test Topology — z1 and z2 are SRv6 EVPN PEs on a direct underlay link, each a
  root + leaf for VNI 10. Each runs the cradle engine, which encaps BUM toward
  the remote End.DT2M SID and decaps a replicated copy onto its bridge.
  ```
   z1 [br10: vxlan10 + oport1 + host1]      z2 [br10: vxlan10 + iport2 + host2]
        host1 ─(inject bare BUM)                     host2 ─(capture)
          │                                            ▲
        br10 ─ cradle ═encap═► z1z2 ═════ z2z1 ═decap═ cradle ─ br10
  ```

  Scenario: Build the SRv6 EVPN topology and confirm the SR P2MP exchange
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1z2" to namespace "z2" interface "z2z1"
    # Deterministic underlay MACs (the cradle engine resolves the next hop itself).
    And I execute "ip link set z1z2 address 02:00:00:00:12:01" in namespace "z1"
    And I execute "ip link set z2z1 address 02:00:00:00:12:02" in namespace "z2"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    # Per-node L2 domain: a VNI-10 bridge with an overlay port (encap egress),
    # a leaf flood-in port (decap target), and an access port.
    And I execute "ip link add br10 type bridge" in namespace "z1"
    And I execute "ip link set vxlan10 master br10" in namespace "z1"
    And I execute "ip link add oport1 type veth peer name oport1p" in namespace "z1"
    And I execute "ip link add host1 type veth peer name host1p" in namespace "z1"
    And I execute "ip link set oport1 master br10" in namespace "z1"
    And I execute "ip link set host1 master br10" in namespace "z1"
    And I execute "ip link set br10 up" in namespace "z1"
    And I execute "ip link set oport1 up" in namespace "z1"
    And I execute "ip link set oport1p up" in namespace "z1"
    And I execute "ip link set host1 up" in namespace "z1"
    And I execute "ip link set host1p up" in namespace "z1"
    And I execute "ip link add br10 type bridge" in namespace "z2"
    And I execute "ip link set vxlan10 master br10" in namespace "z2"
    And I execute "ip link add iport2 type veth peer name iport2p" in namespace "z2"
    And I execute "ip link add host2 type veth peer name host2p" in namespace "z2"
    And I execute "ip link set iport2 master br10" in namespace "z2"
    And I execute "ip link set host2 master br10" in namespace "z2"
    And I execute "ip link set br10 up" in namespace "z2"
    And I execute "ip link set iport2 up" in namespace "z2"
    And I execute "ip link set iport2p up" in namespace "z2"
    And I execute "ip link set host2 up" in namespace "z2"
    And I execute "ip link set host2p up" in namespace "z2"
    And I wait 12 seconds for BGP to operate
    Then BGP session in "z1" to "2001:db8:12::2" should be "Established"
    # z1 learns z2's per-PE IMET carrying z2's End.DT2M SID (SRv6 L2 Prefix-SID).
    And show command "show bgp evpn" in namespace "z1" should eventually contain "[3]:[0]:[128]:[2001:db8::2]"

  Scenario: The cradle engine is programmed with the SRv6 EVPN replication datapath
    Given the test topology exists
    # Both PEs spawned + attached the managed cradle engine under `system ebpf`.
    Then show command "show ebpf" in namespace "z1" should eventually contain "managed"
    And show command "show ebpf" in namespace "z2" should eventually contain "managed"
    # Each PE installed its own End.DT2M leaf SID into the engine's SRv6 table
    # (leaf decap; teed via AddLocalSid — the datapath the retired offload's
    # End.DT2M child used to provide).
    And show command "show ebpf srv6" in namespace "z1" should eventually contain "fcbb:bbbb:1:"
    And show command "show ebpf srv6" in namespace "z2" should eventually contain "fcbb:bbbb:2:"
    # And z1 programmed z2's remote End.DT2M SID as a VNI-10 replication slot —
    # the root fan-out (CradleReplAdd -> AddReplSlot) the offload's H.Encaps
    # child used to do.
    And daemon log in namespace "z1" should eventually contain "repl slot"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
