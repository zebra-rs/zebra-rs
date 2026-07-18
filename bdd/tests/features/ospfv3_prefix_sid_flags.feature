@serial
@ospfv3_prefix_sid_flags
@ospf
Feature: OSPFv3 Prefix-SID Sub-TLV flag bit positions (RFC 8666 §7.1)
  As a network operator
  I want zebra-rs to encode the OSPFv3 Prefix-SID Sub-TLV Flags octet at
  the bit positions RFC 8666 §7.1 assigns (shared with RFC 8665 §6 for
  OSPFv2 and matching FRR EXT_SUBTLV_PREFIX_SID_*FLG): NP = 0x40,
  M = 0x20, E = 0x10, V = 0x08, L = 0x04, with the MSB and the low two
  bits reserved — so a Prefix-SID advertised by one router is decoded
  with the correct flags by an interoperable peer.

  Regression coverage for the flag-placement bug where every flag sat
  one bit too high (NP = 0x80, ...): zebra-to-zebra flooding is
  symmetric, so the wire encoding is only observable by rendering the
  Prefix-SID sub-TLV a *peer* decoded from the flooded LSA. o1 and o2
  run OSPFv3 area 0 over one point-to-point link, both on SR-MPLS with a
  loopback Prefix-SID (index 100 / 200 -> labels 16100 / 16200 against
  the default SRGB base 16000). The index form carries NP (no-PHP), so
  each peer must render the other's Prefix-SID flags as exactly
  "0x40 : NP".

  Test Topology:
  ```
   o1 ──────────────── o2
   2001:db8:12::1/64   2001:db8:12::2/64
   lo 2001:db8::1 SID 100   lo 2001:db8::2 SID 200
  ```

  Scenario: Build the OSPFv3 SR-MPLS topology
    Given a clean test environment
    When I create namespace "o1"
    And I create namespace "o2"
    And I connect namespace "o1" interface "o1-o2" to namespace "o2" interface "o2-o1"
    And I start zebra-rs in namespace "o1"
    And I start zebra-rs in namespace "o2"
    And I apply config "o1.yaml" to namespace "o1"
    And I apply config "o2.yaml" to namespace "o2"
    And I wait 10 seconds
    Then ping from "o1" to "2001:db8::2" should eventually succeed
    # Both nodes advertise a Prefix-SID and resolve the peer's label.
    And show command "show mpls ilm" in namespace "o1" should eventually contain "16100"
    And show command "show mpls ilm" in namespace "o1" should eventually contain "16200"

  Scenario: Prefix-SID flags decode at RFC 8666 bit positions on the peer
    Given the test topology exists
    # o2 has parsed o1's flooded E-Intra-Area-Prefix LSA; its Prefix-SID
    # sub-TLV must decode with NP at bit 1 of the octet (0x40, RFC 8666
    # §7.1) — not the old one-bit-high 0x80 placement.
    Then show command "show ospfv3 database detail" in namespace "o2" should contain "Prefix-SID Sub-TLV:"
    And show command "show ospfv3 database detail" in namespace "o2" should contain "Flags: 0x40 : NP"
    And show command "show ospfv3 database detail" in namespace "o2" should contain "SID/Label: Index: 100"
    # The buggy one-bit-high encoding would render NP as 0x80; assert it
    # never appears.
    And show command "show ospfv3 database detail" in namespace "o2" should not contain "0x80 : NP"
    # Symmetric: o1's decode of o2's Prefix-SID (index 200) is identical.
    And show command "show ospfv3 database detail" in namespace "o1" should contain "Flags: 0x40 : NP"
    And show command "show ospfv3 database detail" in namespace "o1" should contain "SID/Label: Index: 200"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "o1"
    And I stop zebra-rs in namespace "o2"
    And I delete namespace "o1"
    And I delete namespace "o2"
    Then the test environment should be clean
