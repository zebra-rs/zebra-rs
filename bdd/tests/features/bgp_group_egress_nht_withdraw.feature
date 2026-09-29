@serial
@bgp_group_egress_nht_withdraw
Feature: The group egress engine withdraws from the first neighbor too
  As a network operator running the per-update-group egress engine
  (ZEBRA_BGP_EGRESS_GROUP_TASK=1)
  I want a route withdrawn because its next-hop stopped resolving to leave
  every neighbor it was sent to
  So no neighbor keeps forwarding to us on a route we no longer have.

  The engine's withdraw skipped the neighbor its caller named as the
  route's source. The next-hop re-evaluation names none and passes 0 —
  the index of the first configured neighbor — so that neighbor kept the
  route. The engine serves IPv4 unicast only, so there is no IPv6 twin.

  Test Topology:
  ```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.65.0/24                      │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   z1    │     │   z3    │     │   h1    │     │   z4    │
    │  (DUT)  │     │  plain  │     │scripted │     │  plain  │
    │ AS65001 │     │ AS65093 │     │ AS65091 │     │ AS65094 │
    │  .1     │     │  .2     │     │  .3     │     │  .4     │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
  ```
  z1 runs the group egress engine. Its neighbors are configured in address
  order, so z3 is the first (index 0), h1 the second and z4 the third; z3
  and z4 share one update group. h1
  (tests/scripts/bgp_attr_inject_send.py) announces 10.65.1.0/24 with the
  third-party next-hop 10.65.99.2, which z1 resolves through the static
  route 10.65.99.0/24 via h1; deleting that route makes it unreachable.

  Config files:
  - z1.yaml: DUT — the static route; eBGP to z3, h1 (passive) and z4.
  - z3.yaml, z4.yaml: z1's plain neighbors.

  Scenario: Setup topology; z3 and z4 learn the prefix
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.65.1/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.65.2/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.65.3/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.65.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1" with egress group task
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "z4.yaml" to namespace "z4"
    Then BGP session in "z1" to "192.168.65.2" should eventually be "Established"
    And BGP session in "z1" to "192.168.65.4" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.65.1 65091 192.168.65.3 4 10.65.99.2 /tmp/bgp_group_egress_nht_withdraw 10.65.1.0/24" in namespace "h1"
    Then BGP session in "z1" to "192.168.65.3" should eventually be "Established"
    And the zebra-rs log in namespace "z1" should contain "BGP egress group task: spawned"
    And show command "show bgp" in namespace "z3" should eventually contain "10.65.1.0/24"
    And show command "show bgp" in namespace "z4" should eventually contain "10.65.1.0/24"

  Scenario: The next-hop stops resolving; both neighbors lose the route
    Given the test topology exists
    When I apply command "delete router static ipv4 route 10.65.99.0/24" in namespace "z1"
    # Control: the third neighbor was always withdrawn.
    Then show command "show bgp" in namespace "z4" should eventually not contain "10.65.1.0/24"
    # Pre-fix the first neighbor kept the route.
    And show command "show bgp" in namespace "z3" should eventually not contain "10.65.1.0/24"
    And BGP session in "z1" to "192.168.65.2" should be "Established"

  Scenario: The next-hop resolves again; both neighbors get the route back
    Given the test topology exists
    When I apply command "set router static ipv4 route 10.65.99.0/24 nexthop 192.168.65.3" in namespace "z1"
    Then show command "show bgp" in namespace "z3" should eventually contain "10.65.1.0/24"
    And show command "show bgp" in namespace "z4" should eventually contain "10.65.1.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I delete namespace "z1"
    And I delete namespace "z3"
    And I delete namespace "h1"
    And I delete namespace "z4"
    And I delete bridge "br0"
    Then the test environment should be clean
