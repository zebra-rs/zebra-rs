@serial
@bgp_unnumbered_multipath
Feature: BGP multipath over IPv6-unnumbered interface neighbors
  As a network operator running an eBGP Clos fabric on unnumbered links
  I want equal-cost RFC 8950 paths (v6 link-local next-hop, one per
  uplink) installed together as one ECMP route
  So that a leaf with several unnumbered uplinks load-shares instead of
  pinning all traffic to a single spine (issue #2318 — the multipath
  dedup keyed on the next-hop attribute, which an ENHE path does not
  have, so every unnumbered path collapsed into a "duplicate" of the
  winner and `maximum-paths` silently did nothing).

  Test Topology (both links P2P veth, link-local only — no v4 or
  global-v6 addresses anywhere on them):
  ```
         ┌─────────┐              ┌─────────┐
         │   z2    │              │   z3    │
         │ AS65000 │              │ AS65000 │
         │ id 10.0.│              │ id 10.0.│
         │  0.101  │              │  0.102  │
         └────┬────┘              └────┬────┘
             (i1)                     (i1)
              │                        │
             P2P                      P2P
              │                        │
             (i1)                     (i2)
         ┌────┴────────────────────────┴────┐
         │           z1  (DUT)              │
         │      AS65031, id 10.0.0.31       │
         │   afi-safi ipv4 maximum-paths 8  │
         └──────────────────────────────────┘
  ```

  z2 and z3 share AS 65000 and both advertise 10.99.0.0/24, so the two
  ENHE paths z1 learns tie on every best-path comparison — the
  multipath-eligible case, matching the issue's leaf-and-spines fabric.
  The expected FIB entry on z1 is FRR-style v4-over-v6 ECMP:
  `nexthop via inet6 fe80::.. dev i1` + `nexthop via inet6 fe80::.. dev i2`.

  Config files (two-step bring-up per node, same RA race as
  bgp_unnumbered_neighbor — see z1-base.yaml for why):
  - z1-base.yaml / z1-full.yaml: DUT; full adds RA on i1+i2, the two
    interface-neighbors, and `afi-safi ipv4 maximum-paths 8`
  - z2-base.yaml / z2-full.yaml: AS 65000, network 10.99.0.0/24
  - z3-base.yaml / z3-full.yaml: same as z2 with its own router-id

  Scenario: Setup topology
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I create namespace "z3"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I connect namespace "z1" interface "i2" to namespace "z3" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2-base.yaml" to namespace "z2"
    And I apply config "z3-base.yaml" to namespace "z3"
    And I wait 2 seconds

  Scenario: Two equal-cost ENHE paths install as one v4-over-v6 ECMP route
    Given the test topology exists
    When I apply config "z1-full.yaml" to namespace "z1"
    And I apply config "z2-full.yaml" to namespace "z2"
    And I apply config "z3-full.yaml" to namespace "z3"
    Then BGP session in namespace "z2" should eventually be "Established"
    And BGP session in namespace "z3" should eventually be "Established"
    # Both legs carry the v6 link-local gateway of their own uplink —
    # the `nexthop` keyword only appears in the kernel's multipath
    # rendering, so its presence alone proves the route went ECMP.
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "nexthop via inet6 fe80::"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "dev i1"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "dev i2"
    And show command "show bgp" in namespace "z1" should eventually contain "*="

  Scenario: Losing one unnumbered uplink leaves the other leg installed
    Given the test topology exists
    # z2-base removes the interface-neighbor (whole-config replace), so
    # its session drops and z1 must fall back to a single-leg route via
    # the surviving uplink — the issue's failover case, which worked
    # even before the fix.
    When I apply config "z2-base.yaml" to namespace "z2"
    Then kernel route "10.99.0.0/24" in namespace "z1" should eventually not contain "dev i1"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "via inet6 fe80::"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "dev i2"

  Scenario: The uplink coming back restores the second leg
    Given the test topology exists
    When I apply config "z2-full.yaml" to namespace "z2"
    Then BGP session in namespace "z2" should eventually be "Established"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "nexthop via inet6 fe80::"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "dev i1"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "dev i2"

  Scenario: Lowering maximum-paths at runtime collapses the ENHE set
    Given the test topology exists
    # The issue's other observation was that a runtime `set … commit`
    # changed nothing either. Dropping to 1 must withdraw the surplus
    # leg, leaving a flat (non-`nexthop`) route via the tie-break
    # winner — z2 has the lower router-id, so its uplink i1 survives.
    When I apply command "set router bgp afi-safi ipv4 maximum-paths 1" in namespace "z1"
    Then kernel route "10.99.0.0/24" in namespace "z1" should eventually not contain "nexthop via"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "via inet6 fe80::"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "dev i1"

  Scenario: Raising maximum-paths at runtime rediscovers the second leg
    Given the test topology exists
    When I apply command "set router bgp afi-safi ipv4 maximum-paths 8" in namespace "z1"
    Then kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "nexthop via inet6 fe80::"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "dev i1"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "dev i2"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    Then the test environment should be clean
