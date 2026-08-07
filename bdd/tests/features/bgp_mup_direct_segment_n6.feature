@serial
@bgp_mup_direct_segment_n6
Feature: BGP MUP Direct segment in the N6 VRF, ST2 in the N3 VRF
  As a network operator
  I want the `mup-ext-comm` correlation to work across VRFs — a Type-2
  Session-Transformed (ST2) route originated by the RAN-facing N3 VRF
  resolving to the Direct Segment Discovery (DSD) route originated by the
  internet-facing N6 VRF — because the segment an ST2 resolves to selects
  the table its uplink traffic is looked up in after GTP decap: the Direct
  segment must live in the N6 routing context so internet-bound subscriber
  packets never route through the RAN-facing N3 table. This is the two-VRF
  example in the BGP MUP book chapter (ch-02-35).

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

  z1 is a combined UPF + controller with the book's two-VRF split: VRF N3
  (rd 65000:100, `encapsulation srv6`) holds `route st2 network-instance
  core mup-ext-comm 1:2`; VRF N6 (rd 65000:200, `encapsulation srv6`)
  holds `segment direct mup-ext-comm 1:2`. One `pfcp-inject` session on
  Network Instance `core` originates the ST2 under N3's RD; the DSD
  originates under N6's RD. z2 (`afi-safi mup segment interwork`) receives
  both and resolves the ST2 to the N6 Direct segment purely by the shared
  Direct-segment id 1:2 — across VRFs and RDs.

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

  Scenario: One PFCP session originates the ST2 under N3's RD, the DSD under N6's
    Given the test topology exists
    When I execute "pfcp-inject --target 127.0.0.1 --port 8805 --ue-ipv4 192.0.2.5 --teid 0x12345678 --endpoint 10.0.0.1 --core-endpoint 10.0.0.1 --core-teid 0x12345678 --network-instance core" in namespace "z1"
    Then show command "show bgp mup" in namespace "z1" should eventually contain "[DSD][65000:200][10.0.0.1]"
    And show command "show bgp mup" in namespace "z1" should eventually contain "[ST2][65000:100][ep=10.0.0.1][teid=305419896]"
    # The split holds per VRF: the ST2 belongs to N3, the DSD to N6.
    And show command "show bgp vrf N3 mup" in namespace "z1" should contain "[ST2]"
    And show command "show bgp vrf N6 mup" in namespace "z1" should contain "[DSD]"
    # z1 declares direct, not interwork, so it shows no resolution.
    And show command "show bgp mup" in namespace "z1" should not contain "resolved mup:1:2"

  Scenario: z2 (interwork) resolves the N3 ST2 to the N6 Direct segment across RDs
    Given the test topology exists
    Then show command "show bgp mup" in namespace "z2" should eventually contain "[ST2][65000:100][ep=10.0.0.1][teid=305419896]"
    And show command "show bgp mup" in namespace "z2" should contain "[DSD][65000:200][10.0.0.1]"
    # The ST2's Direct-segment id (1:2) — not its VRF or RD — picks the
    # segment: uplink traffic decaps into the N6 routing context.
    And show command "show bgp mup" in namespace "z2" should eventually contain "resolved mup:1:2 -> End.DT46"
    And show command "show bgp mup" in namespace "z2" should contain "(via [DSD][65000:200][10.0.0.1])"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
