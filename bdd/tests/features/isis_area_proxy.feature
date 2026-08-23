@isis_area_proxy
@isis
Feature: IS-IS Area Proxy (RFC 9666) — an L1 area appears as one L2 node
  As a network operator
  I want an entire Level-1 area to provide Level-2 transit while appearing
  to the outside backbone as a single proxy node, so that the backbone's
  LSDB stays small: the area elects an Area Leader, distributes a Proxy
  System ID, originates one Proxy LSP for the whole area, sources boundary
  IIHs/SNPs from the proxy identity, and filters the area's own L2 LSPs at
  the boundary — while inside routers still compute working routes to
  destinations beyond the boundary (RFC 9666 Section 3.2 SPF rules).

  All links are point-to-point veth pairs, IPv4. On router rI the
  interface toward rJ is named "iJ".

  Test Topology:
  ```
        Inside Area 49.0001 (all L1L2, area-proxy)      Outside (area 49.0002)
    ┌────────────────────────────────────────────┐   ┌─────────────────────┐
        r1 ─────────── r2 ─────────── r3 ═══════════ r4 ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄ r5
     (candidate     (candidate     (candidate,      (L2-only)        (L2-only,
      priority 100)  priority 50)   priority 10,                      "beyond")
                                    edge: i4 is
                                    level-2-only
                                    => Outside)
    loopbacks: rI -> 10.0.0.I/32
    links:     r1-r2 10.0.12.0/30  r2-r3 10.0.23.0/30  r3-r4 10.0.34.0/30
               r4-r5 10.0.45.0/30
  ```

  Every inside router carries the same proxy-system-id 0000.0000.00aa and
  proxy hostname "zaparea" (RFC 9666: all candidates SHOULD be
  preconfigured identically so a leadership change keeps the proxy
  identity stable). r3's circuit toward r4 is circuit-type level-2-only,
  so it derives as an Outside Circuit without explicit marking. r5 hangs
  one hop beyond the boundary router, proving both that the abstraction
  propagates deeper into the backbone and that inside routers route to
  destinations past the Area Proxy Boundary.

  Scenario: The area elects a leader, reaches readiness, and originates the Proxy LSP
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I create namespace "r4"
    And I create namespace "r5"
    And I connect namespace "r1" interface "i2" to namespace "r2" interface "i1"
    And I connect namespace "r2" interface "i3" to namespace "r3" interface "i2"
    And I connect namespace "r3" interface "i4" to namespace "r4" interface "i3"
    And I connect namespace "r4" interface "i5" to namespace "r5" interface "i4"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I start zebra-rs in namespace "r4"
    And I start zebra-rs in namespace "r5"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    And I apply config "r4.yaml" to namespace "r4"
    And I apply config "r5.yaml" to namespace "r5"
    # The outside adjacency can only form AFTER the inside area converges
    # (r3 must not send boundary IIHs before it learns the Proxy System
    # ID), so allow the full two-stage bring-up.
    And I wait 35 seconds
    # Highest priority wins the RFC 9667 election on every inside router.
    Then show command "show isis area-proxy" in namespace "r1" should contain "this system"
    And show command "show isis area-proxy" in namespace "r1" should contain "priority 100"
    And show command "show isis area-proxy" in namespace "r2" should contain "r1 (priority 100)"
    And show command "show isis area-proxy" in namespace "r3" should contain "r1 (priority 100)"
    # All three inside routers advertise the Area Proxy TLV; the leader
    # observes readiness and distributes the Proxy System ID, which the
    # non-leaders learn from its L2 LSP.
    And show command "show isis area-proxy" in namespace "r1" should contain "3/3 inside routers"
    And show command "show isis area-proxy" in namespace "r1" should contain "READY"
    And show command "show isis area-proxy" in namespace "r2" should contain "Proxy System ID: 0000.0000.00aa"
    And show command "show isis area-proxy" in namespace "r3" should contain "Proxy System ID: 0000.0000.00aa"
    # Only the leader originates the Proxy LSP.
    And show command "show isis area-proxy" in namespace "r1" should contain "Proxy LSP:       originating"
    And show command "show isis area-proxy" in namespace "r2" should not contain "originating"
    # r3's boundary circuit derives as Outside from being level-2-only.
    And show command "show isis area-proxy" in namespace "r3" should contain "Outside Circuits: i4"

  Scenario: Outside routers see one proxy node, never the inside topology
    Given the test topology exists
    # The boundary IIHs are sourced from the Proxy System ID, so r4's only
    # neighbor on i3 is the proxy identity (rendered by its hostname from
    # the Proxy LSP), not r3.
    Then show command "show isis neighbor" in namespace "r4" should contain "zaparea"
    And show command "show isis neighbor" in namespace "r4" should not contain "r3"
    # The Proxy LSP reaches the whole backbone — r5 too, one hop beyond.
    And show command "show isis database" in namespace "r4" should contain "zaparea.00-00"
    And show command "show isis database" in namespace "r5" should contain "zaparea.00-00"
    # The inside routers' own L2 LSPs are filtered at the boundary: no
    # inside system-id ever appears in an outside LSDB.
    And show command "show isis database detail" in namespace "r4" should not contain "0000.0000.0001"
    And show command "show isis database detail" in namespace "r4" should not contain "0000.0000.0002"
    And show command "show isis database detail" in namespace "r4" should not contain "0000.0000.0003"
    And show command "show isis database detail" in namespace "r5" should not contain "0000.0000.0003"
    # r4's own LSP advertises its boundary adjacency toward the proxy
    # system-id — the abstraction is in r4's wire-visible topology.
    And show command "show isis database detail" in namespace "r4" should contain "0000.0000.00aa"
    # The Proxy LSP carries the merged inside prefixes (lowest metric per
    # prefix from the area's L1 LSDB).
    And show command "show isis database detail" in namespace "r5" should contain "10.0.0.1/32"
    And show command "show isis database detail" in namespace "r5" should contain "10.0.12.0/30"

  Scenario: Traffic crosses the abstraction in both directions, one hop beyond included
    Given the test topology exists
    # Outside -> inside: routes learned from the Proxy LSP.
    Then show command "show ip route" in namespace "r4" should contain "10.0.0.1/32"
    And show command "show ip route" in namespace "r5" should contain "10.0.0.1/32"
    And show command "show ip route" in namespace "r5" should contain "10.0.12.0/30"
    # Inside -> outside: RFC 9666 Section 3.2 — inside routers ignore the
    # Proxy LSP but resolve the outside routers' proxy-pointing
    # adjacencies back to the edge router, so even the deepest inside
    # router reaches past the boundary router.
    And show command "show ip route" in namespace "r1" should contain "10.0.0.4/32"
    And show command "show ip route" in namespace "r1" should contain "10.0.0.5/32"
    # Inside routers never consume the Proxy LSP as a topology node.
    And show command "show isis topology" in namespace "r1" should not contain "zaparea"
    # Forwarding, end to end and dual-direction.
    And ping from "r5" to "10.0.0.1" should succeed
    And ping from "r1" to "10.0.0.5" should succeed
    And ping from "r4" to "10.0.12.1" should succeed

  Scenario: Area Leader failover regenerates the Proxy LSP from the successor
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    # The dead leader's LSP lingers un-purged; candidacy is displaced by
    # the RFC 9667 reachability gate once L1 SPF sees the adjacency gone
    # (hold-time expiry), and the priority-50 successor takes over.
    And I wait 45 seconds
    Then show command "show isis area-proxy" in namespace "r2" should contain "this system"
    And show command "show isis area-proxy" in namespace "r2" should contain "Proxy LSP:       originating"
    # The backbone keeps a live Proxy LSP across the change and traffic
    # still crosses the boundary.
    And show command "show isis database" in namespace "r4" should contain "zaparea.00-00"
    And ping from "r5" to "10.0.0.2" should succeed
