@serial
@bgp_mup_st2
Feature: BGP MUP Controller originates a Type-2 ST route from a PFCP session
  As a network operator
  I want the zebra-rs BGP MUP Controller (MUP-C) to learn a mobile session
  over PFCP/N4 and originate a Type-2 Session-Transformed route (ST2, SAFI
  85, RFC 9833 / draft-mpmz-bess-mup-safi §3.1.4) for the uplink (N3) — the
  core endpoint + GTP TEID with the BGP MUP Extended Community of the Direct
  segment — so a peer zebra-rs receives it and the End.DT46 uplink/downlink
  forwarding model can be programmed from the Direct segment.

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

  z1 runs the controller (PFCP listener on 192.168.0.1:8805, locator LOC1,
  VRF `mobile-up` with `afi-safi mup segment direct` plus `route st2
  network-instance core` binding Network Instance `core` to its Type-2 ST /
  Direct segment, and carrying the Direct segment id `1:2` on both the
  segment and the st2 route). `pfcp-inject` plays the SMF: it
  sends an Association Setup + Session Establishment for endpoint 10.0.0.1 /
  TEID 0x12345678 (Network Instance `core`), so z1 originates the ST2 route
  and advertises it to z2.

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

  Scenario: PFCP session establishment originates an ST2 route received by the peer
    Given the test topology exists
    When I execute "pfcp-inject --target 192.168.0.1 --port 8805 --ue-ipv4 192.0.2.5 --teid 0x12345678 --endpoint 10.0.0.1 --network-instance core" in namespace "z1"
    # PFCP ingest learned the session.
    Then show command "show bgp mup-c session" in namespace "z1" should eventually contain "192.0.2.5"
    # z1 originates the Type-2 ST: core endpoint + the full 32-bit GTP TEID
    # (0x12345678 = 305419896). A TEID of 0 here would mean the endpoint
    # length dropped it from the wire.
    And show command "show bgp mup" in namespace "z1" should contain "[ST2][65000:100][ep=10.0.0.1][teid=305419896]"
    # The ST2 carries the export route-target and the Direct segment id
    # (MUP Extended Community 1:2), both rendered in the RD/RT 2:4 form.
    And show command "show bgp mup" in namespace "z1" should contain "rt:65000:200 mup:1:2"
    # The peer receives the ST2 with the TEID and the Direct segment id.
    And show command "show bgp mup" in namespace "z2" should eventually contain "[ST2][65000:100][ep=10.0.0.1][teid=305419896]"
    And show command "show bgp mup" in namespace "z2" should contain "rt:65000:200 mup:1:2"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
