@serial
@bgp_evpn_srv6_p2mp
Feature: BGP EVPN BUM over SRv6 P2MP replication (RFC 9524) — daemon-driven offload
  As a network operator
  I want the BGP control plane to drive the tc-evpn-replicate eBPF offload: two
  SRv6 EVPN PEs exchange their End.DT2M SIDs over an SR P2MP IMET, the root
  forms a replication segment, and the daemon spawns + feeds the ingress
  (End.Replicate / End.DT2M) and encap (root H.Encaps) children that move BUM.

  This proves the control-plane -> supervisor -> loader integration end to end
  (session, SID exchange, ReplSeg, child spawn). Each datapath's actual packet
  forwarding is proven standalone by the tc-evpn-replicate veth scripts in
  cradle-rs (crates/tc-evpn-replicate/scripts/veth-*.sh — End.Replicate,
  End.DT2M, H.Encaps); wiring the netns packet capture through all three is a
  follow-up.

  Test Topology — z1 and z2 are SRv6 EVPN PEs on a direct underlay link, each a
  root + leaf for VNI 10. z1 sources a BUM frame on its access port; the offload
  encaps it toward z2's End.DT2M SID; z2 decaps it onto its bridge.
  ```
   z1 [br10: vxlan10 + oport1(encap) + host1]      z2 [br10: vxlan10 + iport2(leaf) + host2]
        host1 ─(inject bare BUM)                              host2 ─(capture)
          │                                                     ▲
        br10 ─ oport1 ═encap═► z1z2 ═══════════ z2z1 ═decap═► iport2 ─ br10
  ```

  Scenario: Build the SRv6 EVPN topology and confirm the SR P2MP exchange
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1z2" to namespace "z2" interface "z2z1"
    # Fixed underlay MACs so each side's sr-p2mp-dataplane next-hop-mac is known.
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

  Scenario: The daemon spawns the offload children and programs the tree
    Given the test topology exists
    # The control plane forms an SR P2MP ReplSeg and feeds the tc-evpn-replicate
    # ingress + encap children (root H.Encaps toward z2's leaf SID, leaf decap).
    Then daemon log in namespace "z1" should eventually contain "spawned"
    And daemon log in namespace "z1" should eventually contain "ReplSeg add"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
