@serial
@bgp_shard_redistribute_v4
Feature: BGP IPv4 redistribution under RIB sharding (N>1)

  At N>1 the worker pool owns the IPv4-unicast Loc-RIB, and main's shard is
  only its read replica. A redistributed IPv4 route was written to the
  replica, as `network` was before it was moved onto the pool. The pool's
  session-up dump never had it, so a neighbor that established after the
  route was redistributed never learned it. And the pool's best-path never
  saw it, so a peer's path for the same prefix won, despite the
  redistributed route's weight of 32768.

  Now `route_redist_inject` and `route_redist_withdraw` dispatch an
  `OriginateV4` to the pool shard that owns the prefix, carrying the
  source's path-id and the metric as MED, as `route_add` and `route_del`
  do.

  z1 is the sharded device under test (4 shards). It redistributes three
  static routes before either neighbor is configured, so z2 and z3 can only
  learn them from the session-up dump. z3 also originates 10.50.1.0/24.

  Test Topology:
  ```
  z2 (AS65002) ── z1 (AS65001, 4 shards) ── z3 (AS65003)
   10.0.0.2/24    10.0.0.1/24                10.0.0.3/24
                  redistributes static       originates 10.50.1.0/24
                  10.50.1.0/24
                  10.50.2.0/24
                  10.50.3.0/24
  ```
  All three on bridge br0.

  Scenario: z1 redistributes before its neighbors come up
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "10.0.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "10.0.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "10.0.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I wait 3 seconds for BGP to operate
    Then the zebra-rs log in namespace "z1" should contain "BGP RIB sharding: 4 shards (from config)"
    And show command "show bgp ipv4" in namespace "z1" should contain "10.50.2.0/24"
    When I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "10.0.0.2" should eventually be "Established"
    And BGP session in "z1" to "10.0.0.3" should eventually be "Established"

  Scenario: a neighbor that came up later learns the redistributed routes
    Given the test topology exists
    Then show command "show bgp ipv4" in namespace "z2" should eventually contain "10.50.2.0/24"
    And show command "show bgp ipv4" in namespace "z2" should contain "10.50.3.0/24"
    And show command "show bgp ipv4" in namespace "z2" should contain "10.50.1.0/24"

  Scenario: the redistributed route stays best over z3's path for the same prefix
    Given the test topology exists
    # z1 holds z3's path as a candidate, so the check on z2 below is not
    # vacuous. z2 learns only z1's best path: through z3 it would carry
    # AS_PATH "65001 65003".
    Then show command "show bgp ipv4 10.50.1.0/24" in namespace "z1" should contain "65003"
    And show command "show bgp ipv4 10.50.1.0/24" in namespace "z2" should contain "10.50.1.0/24"
    And show command "show bgp ipv4 10.50.1.0/24" in namespace "z2" should not contain "65003"

  Scenario: removing static routes withdraws their redistributed routes
    Given the test topology exists
    # 10.50.2.0/24 is withdrawn outright; 10.50.1.0/24 falls back to z3's
    # path, which z2 now sees through z3 (the output does show "65003" when
    # z3's path is best); 10.50.3.0/24 stays.
    When I apply config "z1-withdraw.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp ipv4" in namespace "z2" should not contain "10.50.2.0/24"
    And show command "show bgp ipv4" in namespace "z2" should contain "10.50.3.0/24"
    And show command "show bgp ipv4 10.50.1.0/24" in namespace "z2" should contain "65003"

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
