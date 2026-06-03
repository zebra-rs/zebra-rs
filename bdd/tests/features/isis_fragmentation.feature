@isis_fragmentation
@isis
Feature: IS-IS LSP fragmentation under a tight lsp-mtu-size
  As a network operator
  I want zebra-rs to fragment its self-originated LSP across multiple
  PDUs when the TLV content exceeds `lsp-mtu-size`, deliver every
  fragment to peers via the standard flooding path, and have the
  receiver correctly merge those fragments back into a single logical
  origin so SPF can still install routes to the originator's loopback.

  Test Topology:
  ```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
       2001:db8:1::1/64   2001:db8:1::2/64
            (vz1ns)             (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          │ MTU 400 │     │         │
          │ 40 net  │     │         │
          └─────────┘     └─────────┘
   lo: 2001:db8:0:ffff::1   lo: 2001:db8:0:ffff::2
              /128                  /128
  ```

  Config files:
  - z1-1.yaml: lsp-mtu-size 400 + 40 IPv6 networks. Forces the packer
    to spread TLV 236 entries across multiple LSP fragments.
  - z2-1.yaml: default config; verifies the receiver-side rebuild from
    a fragmented peer LSP works end-to-end.

  Scenario: Setup fragmentation topology
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with loopback and veth interface on the bridge "br0"
    And I create namespace "z2" with loopback and veth interface on the bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 20 seconds
    Then ping from "z1" to "2001:db8:1::2" should succeed
    And ping from "z2" to "2001:db8:1::1" should succeed

  Scenario: lsp-mtu-size shows up in show isis summary
    Given the test topology exists
    Then show command "show isis summary" in namespace "z1" should contain "LSP MTU: 400 bytes"

  Scenario: z2 observes z1's self-LSP as multiple fragments
    Given the test topology exists
    Then show command "show isis database" in namespace "z2" should contain "Fragment Summary"
    And show command "show isis database" in namespace "z2" should contain "z1.00"

  Scenario: z2 reaches z1's loopback despite z1's self-LSP being fragmented
    Given the test topology exists
    Then ping from "z2" to "2001:db8:0:ffff::1" should succeed
    And ping from "z1" to "2001:db8:0:ffff::2" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
