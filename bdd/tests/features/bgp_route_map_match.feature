@serial
@bgp_route_map_match
Feature: BGP route-map match clauses
  As a network operator
  I want zebra-rs policy-list entries to filter received routes by
  as-path-set, next-hop-set, MED comparison, and origin, so that
  inbound policy can express the same conditions as IOS-XR RPL.

  All four match types are exercised against an established eBGP session
  by swapping z2's input policy and asserting which advertised prefixes
  appear in z2's RIB. z1 attaches an outbound policy that stamps MED=100
  on every advertised route so MED match scenarios have something
  deterministic to compare against.

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
  ```

  Config files:
  - z1.yaml: AS 65001, advertises 10.0.0.1/32 + 10.0.0.2/32, outbound
    SET-MED-100 stamps MED=100 on every route.
  - z2-base.yaml: AS 65002, no input policy; baseline that accepts both
    routes.
  - z2-aspath-pass.yaml: input policy `match as-path-set FROM-65001`
    (regex `^65001$`) — matches the single-AS path from z1.
  - z2-aspath-fail.yaml: input policy `match as-path-set FROM-65999`
    (regex `^65999$`) — no route matches.
  - z2-origin-igp.yaml: input policy `match origin igp` — matches
    network-originated routes.
  - z2-origin-egp.yaml: input policy `match origin egp` — no route
    matches.
  - z2-med-eq-pass.yaml: input policy `match med-eq 100` — matches.
  - z2-med-eq-fail.yaml: input policy `match med-eq 999` — no match.
  - z2-med-range-pass.yaml: input policy `match med-ge 50, med-le 200`
    — matches MED=100.
  - z2-med-range-fail.yaml: input policy `match med-ge 200` — MED=100
    is below the floor, no match.
  - z2-nh-pass.yaml: input policy `match next-hop-set PEER-SUBNET`
    where the prefix-set is 192.168.0.0/24 — matches z1's nexthop
    192.168.0.1.
  - z2-nh-fail.yaml: input policy `match next-hop-set WRONG-SUBNET`
    where the prefix-set is 10.10.0.0/16 — no route matches.

  Scenario: Setup topology and establish BGP session with MED-stamping policy
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2-base.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z2" has "10.0.0.2/32"

  Scenario: match as-path-set accepts routes whose AS_PATH matches the regex
    Given the test topology exists
    When I apply config "z2-aspath-pass.yaml" to namespace "z2"
    And I clear namespace "z2" neighbor "192.168.0.1"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z2" has "10.0.0.2/32"

  Scenario: match as-path-set rejects routes whose AS_PATH does not match
    Given the test topology exists
    When I apply config "z2-aspath-fail.yaml" to namespace "z2"
    And I clear namespace "z2" neighbor "192.168.0.1"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" does not have "10.0.0.1/32"
    And BGP route in "z2" does not have "10.0.0.2/32"

  Scenario: match origin igp accepts network-originated routes
    Given the test topology exists
    When I apply config "z2-origin-igp.yaml" to namespace "z2"
    And I clear namespace "z2" neighbor "192.168.0.1"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z2" has "10.0.0.2/32"

  Scenario: match origin egp rejects network-originated (igp) routes
    Given the test topology exists
    When I apply config "z2-origin-egp.yaml" to namespace "z2"
    And I clear namespace "z2" neighbor "192.168.0.1"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" does not have "10.0.0.1/32"
    And BGP route in "z2" does not have "10.0.0.2/32"

  Scenario: match med-eq accepts routes with the exact MED value
    Given the test topology exists
    When I apply config "z2-med-eq-pass.yaml" to namespace "z2"
    And I clear namespace "z2" neighbor "192.168.0.1"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z2" has "10.0.0.2/32"

  Scenario: match med-eq rejects routes with a different MED value
    Given the test topology exists
    When I apply config "z2-med-eq-fail.yaml" to namespace "z2"
    And I clear namespace "z2" neighbor "192.168.0.1"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" does not have "10.0.0.1/32"
    And BGP route in "z2" does not have "10.0.0.2/32"

  Scenario: match med-ge and med-le accept routes inside the range
    Given the test topology exists
    When I apply config "z2-med-range-pass.yaml" to namespace "z2"
    And I clear namespace "z2" neighbor "192.168.0.1"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z2" has "10.0.0.2/32"

  Scenario: match med-ge rejects routes below the floor
    Given the test topology exists
    When I apply config "z2-med-range-fail.yaml" to namespace "z2"
    And I clear namespace "z2" neighbor "192.168.0.1"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" does not have "10.0.0.1/32"
    And BGP route in "z2" does not have "10.0.0.2/32"

  Scenario: match next-hop-set accepts routes whose nexthop is in the prefix-set
    Given the test topology exists
    When I apply config "z2-nh-pass.yaml" to namespace "z2"
    And I clear namespace "z2" neighbor "192.168.0.1"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z2" has "10.0.0.2/32"

  Scenario: match next-hop-set rejects routes whose nexthop is outside the prefix-set
    Given the test topology exists
    When I apply config "z2-nh-fail.yaml" to namespace "z2"
    And I clear namespace "z2" neighbor "192.168.0.1"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" does not have "10.0.0.1/32"
    And BGP route in "z2" does not have "10.0.0.2/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
