@serial
@isis_fragmentation_ipv4
Feature: IS-IS LSP fragmentation (IPv4) at lsp-mtu-size 400 and 1500
  As a network operator
  I want zebra-rs to fragment its self-originated LSP across multiple
  PDUs when the IPv4 TLV 135 (Extended IP Reachability) content exceeds
  `lsp-mtu-size`, deliver every fragment to peers via the standard
  flooding path, and have the receiver correctly merge those fragments
  back into a single logical origin so SPF can still install routes to
  the originator's loopback.

  This is verified at two LSP MTUs over one topology: first a tight
  400-byte cap (fragmentation with only 60 networks), then — after a
  live reconfiguration of z1 — the standard 1500-byte Ethernet MTU
  (fragmentation needs 200 networks), confirming both the small-MTU
  path and that a runtime lsp-mtu-size change re-fragments correctly.

  Test Topology:
  ```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
         10.0.1.1/24      10.0.1.2/24
            (vz1ns)             (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          │ 400→1500│     │         │
          │ 60→200  │     │         │
          └─────────┘     └─────────┘
     lo: 10.255.0.1/32     lo: 10.255.0.2/32
  ```

  Config files:
  - z1-1.yaml: lsp-mtu-size 400 + 60 IPv4 /32 networks. Each /32 entry
    costs 9 wire bytes in TLV 135, so 60 entries (~540 bytes) overflow a
    single 400-byte fragment (373-byte budget after 27 bytes of PDU
    overhead) and force the packer to spread TLV 135 entries across
    multiple fragments.
  - z1-2.yaml: lsp-mtu-size 1500 + 200 IPv4 /32 networks. At the standard
    Ethernet MTU the per-fragment budget is 1473 bytes, so 200 entries
    (~1800 bytes) are needed to still span multiple fragments. Re-applied
    to z1 mid-test to exercise a runtime lsp-mtu-size change.
  - z2-1.yaml: default config; verifies the receiver-side rebuild from a
    fragmented peer LSP works end-to-end at both MTUs.

  Scenario: Setup fragmentation topology at lsp-mtu-size 400
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with loopback and veth interface on the bridge "br0"
    And I create namespace "z2" with loopback and veth interface on the bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 20 seconds
    Then ping from "z1" to "10.0.1.2" should succeed
    And ping from "z2" to "10.0.1.1" should succeed

  Scenario: MTU 400 — lsp-mtu-size shows up in show isis summary
    Given the test topology exists
    Then show command "show isis summary" in namespace "z1" should contain "LSP MTU: 400 bytes"

  Scenario: MTU 400 — z2 observes z1's self-LSP as multiple fragments
    Given the test topology exists
    Then show command "show isis database" in namespace "z2" should contain "Fragment Summary"
    And show command "show isis database" in namespace "z2" should contain "z1.00"

  Scenario: MTU 400 — z2 reaches z1's loopback despite z1's self-LSP being fragmented
    Given the test topology exists
    Then ping from "z2" to "10.255.0.1" should succeed
    And ping from "z1" to "10.255.0.2" should succeed

  Scenario: MTU 400 — z2 installs a /32 network carried in one of z1's higher fragments
    Given the test topology exists
    # The advertised `network` prefixes aren't bound to any interface on
    # z1, so they aren't pingable; instead assert the receiver merged the
    # fragmented TLV 135 by checking the last /32 (placed well past
    # fragment 0) shows up in z2's IS-IS RIB.
    Then show command "show isis route" in namespace "z2" should contain "100.64.0.60/32"

  Scenario: Reconfigure z1 to the standard 1500-byte LSP MTU
    Given the test topology exists
    When I apply config "z1-2.yaml" to namespace "z1"
    And I wait 20 seconds
    Then ping from "z1" to "10.0.1.2" should succeed
    And ping from "z2" to "10.0.1.1" should succeed

  Scenario: MTU 1500 — lsp-mtu-size shows up in show isis summary
    Given the test topology exists
    Then show command "show isis summary" in namespace "z1" should contain "LSP MTU: 1500 bytes"

  Scenario: MTU 1500 — z2 still observes z1's self-LSP as multiple fragments
    Given the test topology exists
    Then show command "show isis database" in namespace "z2" should contain "Fragment Summary"
    And show command "show isis database" in namespace "z2" should contain "z1.00"

  Scenario: MTU 1500 — z2 reaches z1's loopback despite z1's self-LSP being fragmented
    Given the test topology exists
    Then ping from "z2" to "10.255.0.1" should succeed
    And ping from "z1" to "10.255.0.2" should succeed

  Scenario: MTU 1500 — z2 installs a /32 network carried in one of z1's higher fragments
    Given the test topology exists
    # After the runtime MTU change z1 now advertises 200 networks; the
    # last /32 sits well past fragment 0, so its presence in z2's RIB
    # proves the receiver re-merged the freshly re-fragmented LSP.
    Then show command "show isis route" in namespace "z2" should contain "100.64.0.200/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
