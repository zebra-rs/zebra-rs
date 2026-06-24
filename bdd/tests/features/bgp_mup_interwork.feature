@serial
@bgp_mup_interwork
Feature: BGP MUP interwork node resolves ST2 to the Direct segment
  As a network operator
  I want a zebra-rs BGP MUP interwork (SRGW) node — `afi-safi mup segment
  interwork` — to resolve each received Type-2 Session-Transformed (ST2)
  route to the matching Direct Segment Discovery (DSD) route by their BGP
  MUP Extended Community (Direct-segment id), so it knows the End.DT46
  segment a session's uplink GTP tunnel forwards into
  (draft-mpmz-bess-mup-safi §3.3.12, RFC 9433 End.DT46).

  Test Topology:
  ```
        2001:db8::1/128            2001:db8::2/128
       ┌──────────┐  IS-IS L2 SRv6  ┌──────────┐
       │    z1    │═════════════════│    z2    │
       │ UPF +    │   iBGP (mup)    │ interwork│
       │ MUP-C    │                 │  (SRGW)  │
       └──────────┘                 └──────────┘
   z1-z2 2001:db8:0:12::1/64   2001:db8:0:12::2/64
  ```

  z1 is a combined UPF + controller: VRF N6 (`encapsulation srv6`, rd
  65501:10) with `afi-safi mup segment direct mup-ext-comm 1:2
  network-instance core` originates a DSD (End.DT46 SID + Direct-segment id
  1:2) and — when `pfcp-inject` programs a session on Network Instance
  `core` — an ST2 (same id 1:2). z2 has `afi-safi mup segment interwork`,
  receives both, and resolves the ST2 to z1's End.DT46 Direct segment.

  NOTE: needs `pfcp-inject` on the BDD host PATH (cargo build --release -p
  pfcp-inject; copy to /usr/bin) and root netns (kernel VRF + seg6local).

  Scenario: Build topology and establish iBGP with the MUP capability
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 45 seconds
    Then BGP session in "z1" to "2001:db8::2" should be "Established"
    And BGP session in "z2" to "2001:db8::1" should be "Established"
    And show command "show bgp neighbor 2001:db8::2" in namespace "z1" should contain "IPv4 MUP: advertised and received"

  Scenario: z1 originates the DSD and (from PFCP) the ST2, both with id 1:2
    Given the test topology exists
    When I execute "pfcp-inject --target 127.0.0.1 --port 8805 --ue-ipv4 192.0.2.5 --teid 0x12345678 --endpoint 10.0.0.1 --network-instance core" in namespace "z1"
    Then show command "show bgp mup" in namespace "z1" should eventually contain "[DSD][65501:10][10.0.0.1]"
    And show command "show bgp mup" in namespace "z1" should eventually contain "[ST2][65501:10][ep=10.0.0.1][teid=305419896]"
    # z1 is a `segment direct` node, not interwork, so it shows no resolution.
    And show command "show bgp mup" in namespace "z1" should not contain "resolved 1:2"

  Scenario: z2 (interwork) resolves the ST2 to z1's End.DT46 Direct segment
    Given the test topology exists
    Then show command "show bgp mup" in namespace "z2" should eventually contain "[ST2][65501:10][ep=10.0.0.1][teid=305419896]"
    And show command "show bgp mup" in namespace "z2" should contain "[DSD][65501:10][10.0.0.1]"
    # The ST2's Direct-segment id (1:2) resolves to the DSD's End.DT46 SID.
    And show command "show bgp mup" in namespace "z2" should eventually contain "resolved 1:2 -> End.DT46"
    And show command "show bgp mup" in namespace "z2" should contain "(via [DSD][65501:10][10.0.0.1])"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
