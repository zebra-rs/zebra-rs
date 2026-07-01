@serial
@bgp_mup_e2e
Feature: BGP MUP Controller originates Session-Transformed routes from PFCP
  As a network operator
  I want the zebra-rs BGP MUP Controller (MUP-C) to learn a mobile session
  over PFCP/N4 and originate a Type-1 Session-Transformed route (SAFI 85,
  draft-ietf-bess-mup-safi) that a peer zebra-rs receives, so the end-to-end control plane
  — PFCP ingest, NI -> VRF correlation, SRv6 SID allocation, ST route
  origination, and iBGP advertisement — is validated.

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
  VRF `mobile-up` matching Network Instance `access`). `pfcp-inject` plays
  the SMF: it sends an Association Setup + Session Establishment for UE
  192.0.2.5 (Network Instance `access`), so z1 originates the ST1 route and
  advertises it to z2.

  NOTE: this feature runs `pfcp-inject` inside z1, so the `pfcp-inject`
  binary (the test-only SMF simulator, `tools/pfcp-inject`) must be on the
  BDD host PATH — build with `cargo build --release -p pfcp-inject` and
  copy `target/release/pfcp-inject` to /usr/bin, the same way the
  zebra-rs / vtyctl binaries are staged for BDD.

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

  Scenario: PFCP session establishment originates an ST1 route received by the peer
    Given the test topology exists
    When I execute "pfcp-inject --target 192.168.0.1 --port 8805 --ue-ipv4 192.0.2.5 --teid 0x12345678 --endpoint 10.0.0.1 --network-instance access" in namespace "z1"
    Then show command "show bgp mup-c session" in namespace "z1" should eventually contain "192.0.2.5"
    And show command "show bgp mup" in namespace "z1" should contain "ue=192.0.2.5/32"
    And show command "show bgp mup" in namespace "z2" should eventually contain "ue=192.0.2.5/32"
    # The peer-learned route is mirrored into z2's `mobile-up` VRF (it
    # imports the route's RT 65000:200), so the per-VRF view reflects it.
    And show command "show bgp vrf mobile-up mup" in namespace "z2" should eventually contain "ue=192.0.2.5/32"

  # Session deletion / route withdrawal is covered by the `pfcp.rs`
  # `session_deletion_removes_session` unit test and manual validation; a
  # BDD assertion on it is omitted here because `pfcp-inject` is one-shot
  # (establish+delete in a single run) and the controller allocates a fresh
  # SEID per establish, so a back-to-back establish/delete can't be
  # deterministically observed on the receiver across propagation delay.

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
