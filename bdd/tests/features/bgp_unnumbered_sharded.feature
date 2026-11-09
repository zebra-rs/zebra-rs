@serial
@bgp_unnumbered_sharded
Feature: BGP unnumbered neighbor on a router with RIB sharding
  As a network operator running BGP over IPv6-only point-to-point links
  on a router with `rib-sharding` above 1
  I want the IPv4 routes an unnumbered neighbor sends (RFC 8950, IPv6
  link-local next-hop) to leave the kernel FIB when the neighbor
  withdraws them or the session goes down
  So that the router does not keep forwarding into a neighbor that no
  longer offers the route.

  At N>1 the worker pool owns IPv4-unicast selection, and withdraws and
  session clean-up go to the pool. RFC 8950 routes used to be ingested on
  main instead, where the pool's withdraw and peer-down never reached
  them: z1 kept both of z2's routes in its FIB after a withdraw and after
  the session went down. Only z1 is sharded; z2 is the plain neighbor.

  Test Topology (P2P veth, link-local only — no v4/global-v6 addrs on
  i1; the LAN prefixes live on dummy interfaces):
  ```
   10.10.1.0/24 (lan)                      10.10.2.0/24 (lan)
        (i1)                                   (i1)
    ┌────┴────┐                            ┌────┴────┐
    │   z1    │────────── P2P ─────────────│   z2    │
    │ AS65001 │       fe80:: <-> fe80::    │ AS65002 │
    │ shards 2│                            │ 10.0.0. │
    │         │                            │   2/32  │
    └─────────┘                            └─────────┘
  ```

  Config files:
  - z1-base.yaml / z2-base.yaml: a bare `router bgp` block, so ND learns
    i1 before RA is enabled (see bgp_unnumbered_neighbor). z1's already
    carries `rib-sharding 2`: BGP reads the shard count once, at spawn.
  - z1-full.yaml / z2-full.yaml: RA on i1 and `interface-neighbor i1`.
    z2 advertises 10.10.2.0/24 and 10.0.0.2/32 with a zero MRAI.
  - z2-withdraw.yaml: z2-full.yaml without 10.10.2.0/24.

  Scenario: Setup topology
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I create dummy interface "lan" with address "10.10.1.1/24" in namespace "z1"
    And I create dummy interface "lan" with address "10.10.2.1/24" in namespace "z2"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2-base.yaml" to namespace "z2"
    And I wait 2 seconds

  Scenario: The sharded router installs the unnumbered neighbor's IPv4 routes
    Given the test topology exists
    When I apply config "z1-full.yaml" to namespace "z1"
    And I apply config "z2-full.yaml" to namespace "z2"
    Then the zebra-rs log in namespace "z1" should contain "BGP RIB sharding: 2 shards (from config)"
    And BGP session in namespace "z1" should eventually be "Established"
    And BGP session in namespace "z2" should eventually be "Established"
    And kernel route "10.10.2.0/24" in namespace "z1" should eventually contain "via inet6 fe80::"
    And kernel route "10.0.0.2/32" in namespace "z1" should eventually contain "via inet6 fe80::"
    And show command "show bgp ipv4" in namespace "z1" should contain "10.10.2.0/24"
    # The best path is marked `>`. At N>1 the table renders main's read
    # replica of the pool, whose candidates used to keep their
    # pre-selection flags: the line read `*   10.10.2.0/24`.
    And show command "show bgp ipv4" in namespace "z1" should contain "*>  10.10.2.0/24"
    And ping from "z1" to "10.10.2.1" should succeed

  Scenario: A withdrawn route leaves the sharded router's FIB
    Given the test topology exists
    # z2 withdraws 10.10.2.0/24 and keeps the session. Pre-fix the
    # withdraw went to the pool, which did not hold the route, so z1 kept
    # it in its Loc-RIB and FIB.
    When I apply config "z2-withdraw.yaml" to namespace "z2"
    Then kernel route "10.10.2.0/24" in namespace "z1" should eventually be gone
    And show command "show bgp ipv4" in namespace "z1" should not contain "10.10.2.0/24"
    And kernel route "10.0.0.2/32" in namespace "z1" should eventually contain "via inet6 fe80::"
    And BGP session in namespace "z1" should eventually be "Established"
    # Re-announced, the route comes back.
    When I apply config "z2-full.yaml" to namespace "z2"
    Then kernel route "10.10.2.0/24" in namespace "z1" should eventually contain "via inet6 fe80::"

  Scenario: Losing the session removes the routes from the sharded router's FIB
    Given the test topology exists
    # z2 drops the neighbor, which tears the session down. Pre-fix z1's
    # session clean-up went to the pool only, so z1 kept both routes.
    When I apply config "z2-base.yaml" to namespace "z2"
    Then BGP session in namespace "z1" should eventually not be "Established"
    And kernel route "10.10.2.0/24" in namespace "z1" should eventually be gone
    And kernel route "10.0.0.2/32" in namespace "z1" should eventually be gone
    And show command "show bgp ipv4" in namespace "z1" should not contain "10.0.0.2/32"
    And ping from "z1" to "10.10.2.1" should fail

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
