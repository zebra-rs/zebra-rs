@serial
@bgp_mup_dual_st
Feature: BGP MUP Controller originates both ST1 and ST2 from one PFCP session
  As a network operator
  I want the zebra-rs BGP MUP Controller (MUP-C) to originate every
  Session-Transformed route whose VRF binds a session's Network Instance —
  so when a downlink (st1) VRF and an uplink (st2) VRF both bind the same
  Network Instance, a single PFCP/N4 session originates BOTH the Type-1 ST
  (UE prefix + access tunnel) and the Type-2 ST (core endpoint + GTP TEID),
  not just the first matching VRF.

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ MUP-C   │ iBGP│ receiver│
           │192.168. │◄───►│192.168. │
           │  0.1/24 │     │  0.2/24 │
           └────┬────┘     └─────────┘
                │ PFCP/N4 (UDP 8805)
           ┌────┴──────┐
           │ pfcp-inject│  (SMF simulator, run in z1)
           └───────────┘
  ```

  z1 runs the controller (PFCP listener on 192.168.0.1:8805, locator LOC1)
  with two VRFs binding Network Instance `internet`: `mobile-dl`
  (rd 65000:101, `afi-safi mup route st1`) for the downlink Type-1 ST, and
  `mobile-ul` (rd 65000:100, `afi-safi mup route st2` carrying Direct
  segment id `1:2`) for the uplink Type-2 ST. `pfcp-inject` plays the SMF:
  it sends an Association Setup + Session Establishment for UE 192.0.2.5 with
  an ACCESS-side F-TEID (gNB endpoint 10.0.0.1 / TEID 0x12345678) and a
  CORE-side F-TEID (endpoint 10.9.0.1 / TEID 0x87654321), Network Instance
  `internet`. The Type-1 ST carries the access endpoint, the Type-2 ST the
  core endpoint (draft §3.3.7 / §3.3.10 — they are distinct), and z1
  advertises BOTH to z2.

  NOTE: this feature runs `pfcp-inject` inside z1, so the `pfcp-inject`
  binary (`tools/pfcp-inject`) must be on the BDD host PATH — build with
  `cargo build --release -p pfcp-inject` and copy `target/release/pfcp-inject`
  to /usr/bin, the same way the zebra-rs / vtyctl binaries are staged.

  Scenario: Setup topology and establish iBGP session with MUP capability
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "IPv4 MUP: advertised and received"
    And show command "show bgp mup-c" in namespace "z1" should contain "PFCP listen : 192.168.0.1:8805"

  Scenario: One PFCP session originates both an ST1 and an ST2 route received by the peer
    Given the test topology exists
    When I execute "pfcp-inject --target 192.168.0.1 --port 8805 --ue-ipv4 192.0.2.5 --teid 0x12345678 --endpoint 10.0.0.1 --core-endpoint 10.9.0.1 --network-instance internet" in namespace "z1"
    # PFCP ingest learned the single session (with an access-side and a
    # core-side F-TEID).
    Then show command "show bgp mup-c session" in namespace "z1" should eventually contain "192.0.2.5"
    # The downlink VRF (st1) originates a Type-1 ST: UE prefix + the ACCESS
    # tunnel endpoint (gNB, 10.0.0.1), with the Source Address (draft §3.2.1)
    # stamped from the session's core-side endpoint (the UPF anchor) so a
    # `dataplane gtp` receiver can build the GTP4.E outer header.
    And show command "show bgp mup" in namespace "z1" should contain "[ST1][65000:101][ue=192.0.2.5/32][teid=305419896]"
    And show command "show bgp mup" in namespace "z1" should contain "[ep=10.0.0.1:src=10.9.0.1]"
    # The uplink VRF (st2) originates a Type-2 ST from the SAME session with
    # the distinct CORE endpoint (10.9.0.1) + its own TEID (0x87654321), plus
    # the Direct segment id.
    And show command "show bgp mup" in namespace "z1" should contain "[ST2][65000:100][ep=10.9.0.1][teid=2271560481]"
    And show command "show bgp mup" in namespace "z1" should contain "rt:65000:200 mup:1:2"
    # The peer receives both Session-Transformed routes.
    And show command "show bgp mup" in namespace "z2" should eventually contain "[ST1][65000:101][ue=192.0.2.5/32][teid=305419896]"
    And show command "show bgp mup" in namespace "z2" should contain "[ST2][65000:100][ep=10.9.0.1][teid=2271560481]"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
