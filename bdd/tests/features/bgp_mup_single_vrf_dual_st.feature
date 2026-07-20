@serial
@bgp_mup_single_vrf_dual_st
Feature: One MUP VRF binds both st1 and st2 and originates both ST routes
  As a network operator running a UPF with a single N6 interface (issue
  #1947), I want ONE `router bgp vrf` to bind BOTH `afi-safi mup route st1`
  (downlink) and `afi-safi mup route st2` (uplink) to the same Network
  Instance — so a single PFCP/N4 session originates the Type-1 ST (UE
  prefix + access tunnel) AND the Type-2 ST (core endpoint + GTP TEID)
  under ONE RD, instead of requiring two single-direction VRFs (and with
  them two N6-facing interfaces).

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
  with a SINGLE VRF `mobile` (rd 65000:1) whose `afi-safi mup` block binds
  both `route st1` and `route st2` (the st2 entry carrying Direct segment
  id `1:2`) to Network Instance `internet`. `pfcp-inject` plays the SMF: it
  sends an Association Setup + Session Establishment for UE 192.0.2.5 with
  an ACCESS-side F-TEID (gNB endpoint 10.0.0.1 / TEID 0x12345678) and a
  CORE-side F-TEID (endpoint 10.9.0.1 / TEID 0x87654321), Network Instance
  `internet`. z1 originates BOTH Session-Transformed routes from the one
  VRF — both under rd 65000:1 — and advertises them to z2.

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
    # The MUP VRFs block renders BOTH direction bindings on the one VRF line.
    And show command "show bgp mup" in namespace "z1" should contain "mobile: rd=65000:1 encap/ST1 ni=internet decap/ST2 ni=internet"

  Scenario: One PFCP session originates both STs from the single dual-direction VRF
    Given the test topology exists
    When I execute "pfcp-inject --target 192.168.0.1 --port 8805 --ue-ipv4 192.0.2.5 --teid 0x12345678 --endpoint 10.0.0.1 --core-endpoint 10.9.0.1 --network-instance internet" in namespace "z1"
    # PFCP ingest learned the single session (with an access-side and a
    # core-side F-TEID).
    Then show command "show bgp mup-c session" in namespace "z1" should eventually contain "192.0.2.5"
    # The st1 binding originates the Type-1 ST: UE prefix + ACCESS tunnel
    # endpoint (gNB, 10.0.0.1), Source Address from the core-side endpoint.
    And show command "show bgp mup" in namespace "z1" should contain "[ST1][65000:1][ue=192.0.2.5/32][teid=305419896]"
    And show command "show bgp mup" in namespace "z1" should contain "[ep=10.0.0.1:src=10.9.0.1]"
    # The st2 binding originates the Type-2 ST from the SAME session and the
    # SAME VRF/RD: the distinct CORE endpoint (10.9.0.1) + its own TEID
    # (0x87654321), plus the Direct segment id.
    And show command "show bgp mup" in namespace "z1" should contain "[ST2][65000:1][ep=10.9.0.1][teid=2271560481]"
    And show command "show bgp mup" in namespace "z1" should contain "rt:65000:200 mup:1:2"
    # The originating VRF's own view holds BOTH its ST routes (RD-origin
    # self-show) — the single-N6 UPF sees its whole session in one VRF.
    And show command "show bgp vrf mobile mup" in namespace "z1" should contain "[ST1][65000:1][ue=192.0.2.5/32]"
    And show command "show bgp vrf mobile mup" in namespace "z1" should contain "[ST2][65000:1][ep=10.9.0.1]"
    # The peer receives both Session-Transformed routes under the one RD.
    And show command "show bgp mup" in namespace "z2" should eventually contain "[ST1][65000:1][ue=192.0.2.5/32][teid=305419896]"
    And show command "show bgp mup" in namespace "z2" should contain "[ST2][65000:1][ep=10.9.0.1][teid=2271560481]"

  # Session deletion / withdraw of BOTH STs is covered by the
  # `mup_dual_direction_vrf_originates_and_reconciles_both_sts` unit test
  # (bgp/vrf/inst.rs); a BDD assertion is omitted because `pfcp-inject` is
  # one-shot (establish+delete in a single run) and the controller allocates
  # a fresh SEID per establish, so a back-to-back establish/delete can't be
  # deterministically observed on the receiver across propagation delay
  # (same rationale as bgp_mup_e2e.feature).

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
