@isis_l1p2p
@isis
Feature: IS-IS Level-1-only over an all-point-to-point 10-router ladder
  As a network operator
  I want ten zebra-rs instances arranged in a 2x5 "ladder" to form IS-IS
  Level-1 adjacencies over point-to-point links, flood LSPs in a single
  area, and install dual-stack (IPv4 + IPv6) routes to every loopback,
  so that traffic follows the expected primary path, falls back out a
  different interface when the primary link drops, and load-shares across
  the two deliberate equal-cost (ECMP) diamonds.

  All links are point-to-point veth pairs (network-type point-to-point);
  every router is is-type level-1 in area 49.0001. On router zI the
  interface toward zJ is named "iJ".

  Test Topology:
  ```
    z1 --10-- z2 --10-- z3 --10-- z4 --10-- z5     top spine    (metric 10)
    |         |         |         |         |
    40        30        30        30        40       rungs (40 ends / 30 mid)
    |         |         |         |         |
    z6 --20-- z7 --20-- z8 --20-- z9 --20-- z10    bottom spine (metric 20)

    loopbacks: zI -> 10.0.0.I/32  and  2001:db8:0:ffff::I/128
  ```

  Asymmetric spines (top 10 != bottom 20) keep the topology
  primary/backup everywhere except the two end columns, where the rungs
  are bumped to 40 to create exactly two ECMP diamonds: z2<->z6 and
  z4<->z10.

  Scenario: Build the L1-only all-P2P ladder and confirm adjacencies form
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I create namespace "z3"
    And I create namespace "z4"
    And I create namespace "z5"
    And I create namespace "z6"
    And I create namespace "z7"
    And I create namespace "z8"
    And I create namespace "z9"
    And I create namespace "z10"
    And I connect namespace "z1" interface "i2" to namespace "z2" interface "i1"
    And I connect namespace "z2" interface "i3" to namespace "z3" interface "i2"
    And I connect namespace "z3" interface "i4" to namespace "z4" interface "i3"
    And I connect namespace "z4" interface "i5" to namespace "z5" interface "i4"
    And I connect namespace "z6" interface "i7" to namespace "z7" interface "i6"
    And I connect namespace "z7" interface "i8" to namespace "z8" interface "i7"
    And I connect namespace "z8" interface "i9" to namespace "z9" interface "i8"
    And I connect namespace "z9" interface "i10" to namespace "z10" interface "i9"
    And I connect namespace "z1" interface "i6" to namespace "z6" interface "i1"
    And I connect namespace "z2" interface "i7" to namespace "z7" interface "i2"
    And I connect namespace "z3" interface "i8" to namespace "z8" interface "i3"
    And I connect namespace "z4" interface "i9" to namespace "z9" interface "i4"
    And I connect namespace "z5" interface "i10" to namespace "z10" interface "i5"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I start zebra-rs in namespace "z5"
    And I start zebra-rs in namespace "z6"
    And I start zebra-rs in namespace "z7"
    And I start zebra-rs in namespace "z8"
    And I start zebra-rs in namespace "z9"
    And I start zebra-rs in namespace "z10"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "z4.yaml" to namespace "z4"
    And I apply config "z5.yaml" to namespace "z5"
    And I apply config "z6.yaml" to namespace "z6"
    And I apply config "z7.yaml" to namespace "z7"
    And I apply config "z8.yaml" to namespace "z8"
    And I apply config "z9.yaml" to namespace "z9"
    And I apply config "z10.yaml" to namespace "z10"
    And I wait 10 seconds
    # Directly-connected reachability over a top-spine and a rung link,
    # dual-stack, proving the P2P links are up and addressed.
    Then ping from "z1" to "10.0.1.2" should succeed
    And ping from "z1" to "2001:db8:1::2" should succeed
    And ping from "z1" to "10.0.9.2" should succeed
    And ping from "z6" to "2001:db8:5::2" should succeed

  Scenario: L1 installs reciprocal dual-stack routes to every loopback
    Given the test topology exists
    # End-to-end IPv6 forwarding across the full ladder.
    Then ping from "z1" to "2001:db8:0:ffff::10" should succeed
    And ping from "z10" to "2001:db8:0:ffff::1" should succeed
    And ping from "z5" to "2001:db8:0:ffff::6" should succeed
    # End-to-end IPv4 forwarding across the full ladder.
    And ping from "z1" to "10.0.0.10" should succeed
    And ping from "z10" to "10.0.0.1" should succeed
    And ping from "z5" to "10.0.0.6" should succeed
    # The far loopbacks are present in z1's IS-IS RIB.
    And show command "show isis route" in namespace "z1" should contain "10.0.0.5/32"
    And show command "show isis route" in namespace "z1" should contain "10.0.0.10/32"

  Scenario: Primary path fails over to a different interface (z1 -> z5)
    Given the test topology exists
    # Primary z1->z5 is the top spine (cost 40) egressing i2; the only
    # alternative is the long bottom path (cost 160) egressing i6.
    Then show command "show isis route" in namespace "z1" should contain "10.0.0.5/32"
    And ping from "z1" to "10.0.0.5" should succeed
    When I make namespace "z1" interface "i2" down
    And I wait 5 seconds
    # Reconverged onto the backup out the other interface (i6).
    Then ping from "z1" to "10.0.0.5" should succeed
    And ping from "z1" to "2001:db8:0:ffff::5" should succeed
    When I make namespace "z1" interface "i2" up
    And I wait 10 seconds
    # Primary restored.
    Then ping from "z1" to "10.0.0.5" should succeed
    And ping from "z1" to "2001:db8:0:ffff::5" should succeed

  Scenario: The two deliberate ECMP diamonds resolve (z2->z6 and z4->z10)
    Given the test topology exists
    # Left diamond: z2 reaches z6 at cost 50 via i1 (z2-z1-z6) and i7
    # (z2-z7-z6). Right diamond: z4 reaches z10 via i5 and i9.
    Then show command "show isis route" in namespace "z2" should contain "10.0.0.6/32"
    And show command "show isis route" in namespace "z4" should contain "10.0.0.10/32"
    And ping from "z2" to "10.0.0.6" should succeed
    And ping from "z2" to "2001:db8:0:ffff::6" should succeed
    And ping from "z4" to "10.0.0.10" should succeed
    # Dropping one leg of the left diamond (i1) still leaves z2->z6
    # reachable over the surviving ECMP leg (i7).
    When I make namespace "z2" interface "i1" down
    And I wait 5 seconds
    Then ping from "z2" to "10.0.0.6" should succeed
    When I make namespace "z2" interface "i1" up
    And I wait 10 seconds
    Then ping from "z2" to "10.0.0.6" should succeed

  Scenario: IS-IS stamps the level into the central RIB
    Given the test topology exists
    # The IS-IS task tags each route it installs with the level it was
    # computed at; the RIB renders that subtype as the "L1" code column
    # in `show ip route` / `show ipv6 route` (and "level1" in the JSON
    # subtype field). In this Level-1-only topology every IS-IS route is
    # Level-1, so the tag must appear in both address families.
    Then show command "show ip route" in namespace "z1" should contain "L1"
    And show command "show ipv6 route" in namespace "z1" should contain "L1"
    And show command "show ip route" in namespace "z10" should contain "L1"

  Scenario: Area-wide hmac-sha-256 authentication keeps the network converged
    Given the test topology exists
    # Re-apply every router with matching hmac-sha-256 keys: an
    # area-password signs Level-1 LSPs + SNPs (ISO 10589 / RFC 5310) and
    # per-link hello-authentication signs the IIHs. The same key-id 1 /
    # secret is used everywhere, so every adjacency, LSP and SNP verifies.
    # Adding the key to both ends within a few seconds never exceeds the
    # 30s hold-time, so adjacencies ride through the rollover without a
    # bounce (a node with no key configured still accepts a signed PDU).
    When I apply config "z1-auth.yaml" to namespace "z1"
    And I apply config "z2-auth.yaml" to namespace "z2"
    And I apply config "z3-auth.yaml" to namespace "z3"
    And I apply config "z4-auth.yaml" to namespace "z4"
    And I apply config "z5-auth.yaml" to namespace "z5"
    And I apply config "z6-auth.yaml" to namespace "z6"
    And I apply config "z7-auth.yaml" to namespace "z7"
    And I apply config "z8-auth.yaml" to namespace "z8"
    And I apply config "z9-auth.yaml" to namespace "z9"
    And I apply config "z10-auth.yaml" to namespace "z10"
    And I wait 12 seconds
    # Auth is active: the instance summary reports the L1 area-password mode.
    Then show command "show isis summary" in namespace "z1" should contain "Area-password (L1): mode hmac-sha-256"
    And show command "show isis summary" in namespace "z10" should contain "Area-password (L1): mode hmac-sha-256"
    # IIH auth verified: z1's two adjacencies (z2 over i2, z6 over i6) are
    # still Up. The peer renders by dynamic hostname, which only resolves
    # when the peer's LSP was accepted — so this also proves LSP auth.
    And show command "show isis neighbor" in namespace "z1" should contain "z2"
    And show command "show isis neighbor" in namespace "z1" should contain "z6"
    # LSP + SNP auth verified across the area, so the far loopbacks still
    # resolve and end-to-end dual-stack forwarding still works.
    And show command "show isis route" in namespace "z1" should contain "10.0.0.10/32"
    And ping from "z1" to "10.0.0.10" should succeed
    And ping from "z1" to "2001:db8:0:ffff::10" should succeed
    And ping from "z10" to "10.0.0.1" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I stop zebra-rs in namespace "z5"
    And I stop zebra-rs in namespace "z6"
    And I stop zebra-rs in namespace "z7"
    And I stop zebra-rs in namespace "z8"
    And I stop zebra-rs in namespace "z9"
    And I stop zebra-rs in namespace "z10"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "z4"
    And I delete namespace "z5"
    And I delete namespace "z6"
    And I delete namespace "z7"
    And I delete namespace "z8"
    And I delete namespace "z9"
    And I delete namespace "z10"
    Then the test environment should be clean
