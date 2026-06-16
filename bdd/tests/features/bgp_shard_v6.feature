@serial
@bgp_shard_v6
Feature: BGP IPv6-unicast Loc-RIB through the RIB shards (ZEBRA_BGP_SHARDS>1)

  The IPv6 mirror of @bgp_shard_policy. With the RIB partitioned across
  worker shards (ZEBRA_BGP_SHARDS>1), IPv6-unicast routes must flow
  through the pool exactly as IPv4-unicast does — ingest → owning shard →
  reduce → advertise — and the churn paths (withdraw, peer-down) must hit
  the pool too, not the now-empty synchronous shard.

  z2 runs with 4 shards. Correctness is observed DOWNSTREAM on z3 (N=1,
  so its `show` reads a whole table): z1 originates a v6 prefix only after
  every session is Established, so z2 processes it live on the N>1 path.

  IPv6 inbound policy still runs in main (the post-policy decision is sent
  to the shard), so this first cut does not exercise sharded policy /
  soft-reconfig — those land with full v4/v6 parity (compute-policy +
  SoftInV6) as a follow-up, mirrored from @bgp_shard_policy.

  Test Topology:
  ```
  z1 (AS65001) ── z2 (AS65002, 4 shards) ── z3 (AS65003)
  2001:db8::1/64   2001:db8::2/64           2001:db8::3/64
  ```
  All three on bridge br0.

  Scenario: Setup sessions with z2 sharded, before any routes exist
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8::2/64" on bridge "br0"
    And I create namespace "z3" with IP "2001:db8::3/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2" with 4 shards
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "2001:db8::1" should be "Established"
    And BGP session in "z2" to "2001:db8::3" should be "Established"

  Scenario: z1 originates v6 routes; the sharded z2 advertises them to z3
    Given the test topology exists
    When I apply config "z1-routes.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp ipv6" in namespace "z3" should contain "2001:db8:a::1/128"
    And show command "show bgp ipv6" in namespace "z3" should contain "2001:db8:a::2/128"

  Scenario: z1 withdraws one v6 route; the sharded withdraw reaches z3
    Given the test topology exists
    # Replace z1's origination set with one that keeps ::2 but drops ::1, so
    # z1 withdraws ::1. z2 ingests the withdraw at N=4 and the owning pool
    # shard must drop it; ::2 staying is the positive control (session +
    # show still work, so the negative assertion isn't vacuous).
    When I apply config "z1-withdraw1.yaml" to namespace "z1"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp ipv6" in namespace "z3" should not contain "2001:db8:a::1/128"
    And show command "show bgp ipv6" in namespace "z3" should contain "2001:db8:a::2/128"

  Scenario: z1's session drops; sharded peer-down withdraws its v6 routes from z3
    Given the test topology exists
    # z3 still holds ::2 from the previous scenario (positive control). Kill
    # z1 — z2's route_clean must sweep z1's v6-unicast slice on the pool and
    # withdraw ::2 from z3.
    Then show command "show bgp ipv6" in namespace "z3" should contain "2001:db8:a::2/128"
    When I stop zebra-rs in namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "2001:db8::1" should not be "Established"
    And show command "show bgp ipv6" in namespace "z3" should not contain "2001:db8:a::2/128"

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
