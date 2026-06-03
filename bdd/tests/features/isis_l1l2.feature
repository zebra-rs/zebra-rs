@isis_l1l2
@isis
Feature: IS-IS Level-1 / Level-2 interaction across an L1 area and an L2 backbone
  As a network operator
  I want a single L1/L2 router to anchor a Level-1 area on one side and the
  Level-2 backbone on the other, so that it forms the right adjacency level
  per circuit, maintains two independent Link State Databases, runs a
  separate SPF per level, and installs both Level-1 and Level-2 routes at
  the same time — while the two levels stay isolated (an L1 area's internal
  prefixes do not bleed into the L2 backbone, and vice versa).

  All links are point-to-point veth pairs (network-type point-to-point) and
  every router is dual-stack (IPv4 + IPv6). On router rI the interface
  toward rJ is named "iJ".

  Test Topology:
  ```
        Area 49.0001  (Level-1 area)            Backbone (Level-2)
    ┌──────────────────────────────────┐     ┌──────────────────────┐

        r1 ───L1─── r2 ───L1─── r3 ════L2════ r4
       (L1)        (L1)        (L1L2)         (L2-only)
      lo .1        lo .2       lo .3           lo .4
     49.0001      49.0001      49.0001         49.0000

    loopbacks: rI -> 10.0.0.I/32  and  2001:db8::I/128
    links:     r1-r2 10.0.12.0/30  r2-r3 10.0.23.0/30  r3-r4 10.0.34.0/30
               (IPv6 2001:db8:12::/64, 2001:db8:23::/64, 2001:db8:34::/64)
  ```

  r3 is the only Level-1/Level-2 router. Its circuit toward r2 (i2) is
  circuit-type level-1 (same area 49.0001 as r1/r2), and its circuit toward
  r4 (i4) is circuit-type level-2-only. r3's loopback is circuit-type
  level-1-2, so 10.0.0.3/2001:db8::3 is advertised into *both* the L1 LSP
  (reachable from the area) and the L2 LSP (reachable from the backbone).

  Note on scope: zebra-rs builds each level's LSP only from prefixes whose
  circuit participates at that level — there is no automatic L1->L2 leaking
  and the ATT-bit / default-route mechanism is not implemented. So the L1
  area's internal loopbacks (r1, r2) are NOT reachable from the L2-only r4,
  and the L2-only loopback (r4) is NOT reachable from the L1-only r1. The
  final scenario pins that boundary; if inter-level leaking is added later,
  those two negative pings are the assertions to revisit.

  Scenario: Build the topology; the border forms L1 on one side, L2 on the other
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I create namespace "r4"
    And I connect namespace "r1" interface "i2" to namespace "r2" interface "i1"
    And I connect namespace "r2" interface "i3" to namespace "r3" interface "i2"
    And I connect namespace "r3" interface "i4" to namespace "r4" interface "i3"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I start zebra-rs in namespace "r4"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    And I apply config "r4.yaml" to namespace "r4"
    And I wait 25 seconds
    # Directly-connected reachability over the L1 access link and the L2
    # backbone link, dual-stack, proving both P2P circuits are up.
    Then ping from "r1" to "10.0.12.2" should succeed
    And ping from "r1" to "2001:db8:12::2" should succeed
    And ping from "r3" to "10.0.34.2" should succeed
    And ping from "r3" to "2001:db8:34::2" should succeed
    # The border r3 has both adjacency types Up: r2 over i2 at Level-1 and
    # r4 over i4 at Level-2. A peer renders by dynamic hostname only when
    # its LSP was accepted into the matching LSDB, so this also proves the
    # L1 and L2 databases each received their neighbour's LSP.
    And show command "show isis neighbor" in namespace "r3" should contain "r2"
    And show command "show isis neighbor" in namespace "r3" should contain "r4"
    And show command "show isis neighbor" in namespace "r1" should contain "r2"
    And show command "show isis neighbor" in namespace "r4" should contain "r3"

  Scenario: The border keeps two independent Link State Databases
    Given the test topology exists
    # r3 carries both an L1 and an L2 LSDB. The L1 area router r1 only ever
    # appears in an L1 LSP; the L2-only backbone router r4 only ever appears
    # in an L2 LSP — so seeing both on r3 proves the two databases are
    # populated independently. (`detail` prints the per-level section
    # headers; the brief `show isis database` merges both levels.)
    Then show command "show isis database detail" in namespace "r3" should contain "L1 Link State Database"
    And show command "show isis database detail" in namespace "r3" should contain "L2 Link State Database"
    And show command "show isis database detail" in namespace "r3" should contain "r1"
    And show command "show isis database detail" in namespace "r3" should contain "r4"
    # Isolation: the L1-only r1 has no Level-2 database at all, and never
    # learns the backbone-only r4. (format omits an empty level's section.)
    And show command "show isis database detail" in namespace "r1" should contain "L1 Link State Database"
    And show command "show isis database detail" in namespace "r1" should not contain "L2 Link State Database"
    And show command "show isis database detail" in namespace "r1" should not contain "r4"
    # Isolation: the L2-only r4 has no Level-1 database, and never learns the
    # L1 area's internal router r1.
    And show command "show isis database detail" in namespace "r4" should contain "L2 Link State Database"
    And show command "show isis database detail" in namespace "r4" should not contain "L1 Link State Database"
    And show command "show isis database detail" in namespace "r4" should not contain "r1"

  Scenario: The L1/L2 border runs a separate SPF and installs routes at both levels
    Given the test topology exists
    # `show isis route` prints a per-level routing table only when that
    # level's SPF produced results, so both headers on r3 prove it computed
    # Level-1 and Level-2 paths simultaneously.
    Then show command "show isis route" in namespace "r3" should contain "IS-IS L1 IPv4 routing table"
    And show command "show isis route" in namespace "r3" should contain "IS-IS L2 IPv4 routing table"
    # Both level results land in the central RIB: 10.0.0.1/32 is an L1-area
    # loopback (reachable only via Level-1) and 10.0.0.4/32 is the backbone
    # loopback (reachable only via Level-2) — their mere presence on r3
    # proves a route from each level was installed.
    And show command "show ip route" in namespace "r3" should contain "10.0.0.1/32"
    And show command "show ip route" in namespace "r3" should contain "10.0.0.4/32"
    # The border forwards into the L1 area AND across the L2 backbone at the
    # same time, dual-stack.
    And ping from "r3" to "10.0.0.1" should succeed
    And ping from "r3" to "2001:db8::1" should succeed
    And ping from "r3" to "10.0.0.4" should succeed
    And ping from "r3" to "2001:db8::4" should succeed

  Scenario: Forwarding is confined to each level (L1 area + L2 backbone)
    Given the test topology exists
    # Inside area 49.0001 every router reaches every loopback over Level-1,
    # including the L1/L2 border's loopback (advertised into the L1 LSP).
    Then ping from "r1" to "10.0.0.2" should succeed
    And ping from "r1" to "2001:db8::2" should succeed
    And ping from "r1" to "10.0.0.3" should succeed
    And ping from "r1" to "2001:db8::3" should succeed
    And ping from "r2" to "10.0.0.1" should succeed
    And ping from "r2" to "10.0.0.3" should succeed
    # Across the backbone the L2-only r4 reaches the border's loopback
    # (10.0.0.3 is advertised into the L2 LSP because its circuit is L1/L2).
    And ping from "r4" to "10.0.0.3" should succeed
    And ping from "r4" to "2001:db8::3" should succeed
    # The per-level routing tables match each router's role: r1 has only an
    # L1 table, r4 has only an L2 table.
    And show command "show isis route" in namespace "r1" should contain "IS-IS L1 IPv4 routing table"
    And show command "show isis route" in namespace "r1" should not contain "IS-IS L2 IPv4 routing table"
    And show command "show isis route" in namespace "r4" should contain "IS-IS L2 IPv4 routing table"
    And show command "show isis route" in namespace "r4" should not contain "IS-IS L1 IPv4 routing table"

  Scenario: Levels do not leak — the L1 area and the L2 backbone stay separate
    Given the test topology exists
    # zebra-rs does not leak L1 prefixes into L2 (no automatic L1->L2
    # redistribution) and does not implement the ATT-bit default route, so
    # the two ends of the network cannot reach across the L1/L2 boundary:
    #  - the L1-only r1 cannot reach the backbone-only loopback 10.0.0.4,
    #  - the L2-only r4 cannot reach the L1-area-internal loopback 10.0.0.1.
    # These pin the current boundary semantics; revisit if leaking lands.
    Then ping from "r1" to "10.0.0.4" should fail
    And ping from "r1" to "2001:db8::4" should fail
    And ping from "r4" to "10.0.0.1" should fail
    And ping from "r4" to "2001:db8::1" should fail

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I stop zebra-rs in namespace "r4"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    And I delete namespace "r4"
    Then the test environment should be clean
