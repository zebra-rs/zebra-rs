@isis_area_proxy_sr
@isis
Feature: IS-IS Area Proxy with Segment Routing (RFC 9666 SR merges and Area SID)
  As a network operator
  I want an Area-Proxy area running SR-MPLS to present a coherent Segment
  Routing view to the backbone: the Proxy LSP advertises the area's merged
  SRGB (identical starting values required, minimum range) and carries the
  inside prefixes' Prefix-SIDs (P-Flag set, E-Flag reset), plus an anycast
  Area SID that every Inside Edge Router terminates with a label pop — so
  an outside router can steer SR traffic to inside destinations, and to
  "any edge of the area", straight through the abstraction.

  All links are point-to-point veth pairs, IPv4, SR-MPLS everywhere with
  the default SRGB (16000 + index). On router rI the interface toward rJ
  is named "iJ".

  Test Topology:
  ```
      Inside Area 49.0001 (L1L2, area-proxy)      Outside (area 49.0002)
    ┌──────────────────────────────────────┐   ┌──────────────────┐
        r1 ──────────────── r2 ═══════════════ r3
     (candidate 100,     (candidate 50,      (L2-only,
      lo SID index 100)   edge, lo index      lo index 300)
                          200)
    loopbacks: rI -> 10.0.0.I/32
    links:     r1-r2 10.0.12.0/30   r2-r3 10.0.23.0/30
    Area SID:  10.0.0.100/32 index 500 (candidates r1 and r2)
  ```

  Scenario: The Proxy LSP carries the merged SRGB, copied Prefix-SIDs, and the Area SID
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I connect namespace "r1" interface "i2" to namespace "r2" interface "i1"
    And I connect namespace "r2" interface "i3" to namespace "r3" interface "i2"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    And I wait 35 seconds
    # The leader advertises the Area SID alongside the proxy identity;
    # the non-leader edge learns both from the leader's L2 LSP.
    Then show command "show isis area-proxy" in namespace "r1" should contain "Area SID:        10.0.0.100/32 index 500"
    And show command "show isis area-proxy" in namespace "r2" should contain "Area SID:        10.0.0.100/32 index 500"
    # The outside router received the Proxy LSP with the merged inside
    # prefixes and the Area SID anycast prefix.
    And show command "show isis database detail" in namespace "r3" should contain "zaparea.00-00"
    And show command "show isis database detail" in namespace "r3" should contain "10.0.0.1/32"
    And show command "show isis database detail" in namespace "r3" should contain "10.0.0.100/32"

  Scenario: An outside router steers SR-MPLS traffic through the abstraction
    Given the test topology exists
    # The copied Prefix-SID of r1's loopback resolves against the merged
    # SRGB (start 16000): the outside router installs the labeled route
    # 16000 + 100 toward the proxy adjacency. The parenthesized label is
    # the no-PHP rendering — the copied SID carries the P-Flag per
    # RFC 9666 §5.3.6.
    Then show command "show ip route 10.0.0.1/32" in namespace "r3" should eventually contain "label (16100)"
    # The Area SID is a Node SID in the Proxy LSP: label 16000 + 500.
    And show command "show ip route 10.0.0.100/32" in namespace "r3" should eventually contain "label (16500)"
    # The Inside Edge Router terminates the anycast Area SID: a pop ILM
    # for 16500 is installed (RFC 9666: the SID is consumed at the edge).
    And show command "show mpls ilm" in namespace "r2" should eventually contain "16500"
    # Plain reachability through the abstraction still holds under SR.
    And ping from "r3" to "10.0.0.1" should succeed
    And ping from "r1" to "10.0.0.3" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    Then the test environment should be clean
