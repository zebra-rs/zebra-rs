@serial
@isis_csnp_large_lsdb
@isis
Feature: IS-IS CSNP/PSNP with a large LSDB (>15 LSP entries)

  Regression for a TLV 9 (LSP Entries) length-byte overflow. The
  LspEntries TLV's Length field is a single octet and each entry is 16
  bytes, so at most 255 / 16 = 15 entries fit in one TLV. The CSNP and
  PSNP builders, however, sized a single TLV by the MTU budget
  (available_len / 16 ≈ 90 entries at a 1500-byte MTU) rather than by
  that 15-entry ceiling. Once an LSDB held 16 or more LSPs the length
  byte wrapped modulo 256 (16 entries -> 256 -> length 0) while every
  entry was still emitted, so the receiver mis-framed the CSNP/PSNP and
  the DIS-driven database synchronisation was corrupt on the wire. The
  fix caps each LspEntries TLV at MAX_ENTRIES (15); larger LSDBs simply
  span more CSNP/PSNP PDUs.

  This is hard to trigger with a router-per-LSP topology (16+ daemons),
  so instead z1 is given a tight lsp-mtu-size and ~600 IPv4 networks: its
  self-LSP fragments into ~15-20 LSP fragments, each a distinct LSP in
  the LSDB. On the broadcast LAN the elected DIS must therefore list well
  over 15 LSPs in its periodic CSNP. z3 is then brought up *after* z1 and
  z2 have converged, so it must learn the established multi-fragment LSDB
  through the DIS's CSNP (and PSNP requests) rather than from the initial
  flood — making the CSNP path load-bearing.

  Test Topology (all on broadcast LAN br0):
  ```
    z1 (10.255.0.1/32, ~600 nets, lsp-mtu 400)
    z2 (10.255.0.2/32)   -- come up together, converge --
    z3 (10.255.0.3/32)   -- joins late, syncs via the DIS CSNP --
  ```

  Note: the deterministic byte-level regression for the length-byte wrap
  is the `isis-packet` unit test `lsp_entries_over_max_wraps_length_byte`
  / `lsp_entries_at_max_round_trips_with_exact_length`. This feature is
  the live-daemon counterpart: it drives csnp_generate / the PSNP builder
  with a >15-entry LSDB and proves a late joiner fully synchronises.

  Scenario: Setup — z1 (fragmented) and z2 converge on the LAN
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with loopback and veth interface on the bridge "br0"
    And I create namespace "z2" with loopback and veth interface on the bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 40 seconds
    Then ping from "z1" to "10.0.1.2" should eventually succeed
    And ping from "z2" to "10.0.1.1" should eventually succeed

  Scenario: z1's self-LSP fragments into a large (>15-LSP) LSDB
    Given the test topology exists
    # A fragmented self-LSP means z1 originates many LSPs (z1.00-00,
    # z1.00-01, ...); together with z2 and the pseudonode this pushes the
    # LSDB — and thus the DIS's CSNP entry list — past the 15-entry limit.
    Then show command "show isis database" in namespace "z2" should contain "Fragment Summary"
    And show command "show isis database" in namespace "z2" should contain "z1.00"

  Scenario: z2 synchronises the whole LSDB, including z1's highest fragment
    Given the test topology exists
    # 100.64.2.92/32 is the last of z1's ~600 networks, so it lives in one
    # of the highest LSP fragments. Its presence in z2's IS-IS RIB proves
    # z2 received and framed every fragment the DIS advertises.
    Then show command "show isis route" in namespace "z2" should eventually contain "100.64.2.92/32"
    And ping from "z2" to "10.255.0.1" should eventually succeed

  Scenario: A late joiner learns the established large LSDB via the DIS CSNP
    Given the test topology exists
    When I create namespace "z3" with loopback and veth interface on the bridge "br0"
    And I start zebra-rs in namespace "z3"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 40 seconds
    # z3 joins after z1/z2 are already synced, so it learns the >15-LSP
    # database through the DIS's periodic CSNP and its own PSNP requests.
    # With the wrapped-length CSNP this synchronisation was corrupt; z3
    # must now recover the full LSDB — the highest fragment's prefix and
    # both peers' loopbacks — and reach them.
    Then show command "show isis route" in namespace "z3" should eventually contain "100.64.2.92/32"
    And show command "show isis route" in namespace "z3" should eventually contain "10.255.0.1/32"
    And show command "show isis route" in namespace "z3" should eventually contain "10.255.0.2/32"
    And ping from "z3" to "10.255.0.1" should eventually succeed
    And ping from "z3" to "10.255.0.2" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
