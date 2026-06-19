@serial
@bgp_policy_dynamic_update
Feature: BGP reacts to live prefix-set / policy edits without session reset
  As a network operator
  I want zebra-rs to re-evaluate Adj-RIB-In when a referenced prefix-set
  or policy-list is edited, so that operational changes propagate
  immediately without me having to clear the BGP session.

  The exercise: z2 attaches `afi-safi ipv4 policy in HOGE`, where policy HOGE
  matches `prefix-set HOGE`. Because the prefix-set is referenced
  *indirectly* via the policy's match clause, the harness must follow
  the cascade prefix-set HOGE -> policy HOGE -> peer's Adj-RIB-In
  every time the prefix-set is edited. Without the cascade, BGP would
  only see the change after a manual `clear ... soft in`.

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
  - z1.yaml: AS 65001, advertises 1.1.1.1/32 + 2.2.2.2/32, no policy.
  - z2-initial.yaml: prefix-set HOGE = { 1.1.1.1/32 }; policy HOGE matches
    prefix-set HOGE; neighbor applies HOGE inbound; soft-reconfig in.
  - z2-both.yaml: prefix-set HOGE = { 1.1.1.1/32, 2.2.2.2/32 } (added).
  - z2-other.yaml: prefix-set HOGE = { 2.2.2.2/32 } (1.1.1.1/32 removed).

  Scenario: Setup topology and verify initial filter
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2-initial.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP route in "z2" has "1.1.1.1/32"
    And BGP route in "z2" does not have "2.2.2.2/32"

  Scenario: Adding a prefix to the referenced prefix-set propagates without session reset
    Given the test topology exists
    When I apply config "z2-both.yaml" to namespace "z2"
    And I wait 2 seconds for BGP to operate
    Then BGP route in "z2" has "1.1.1.1/32"
    And BGP route in "z2" has "2.2.2.2/32"

  Scenario: Removing a prefix from the referenced prefix-set withdraws the corresponding route
    Given the test topology exists
    When I apply config "z2-other.yaml" to namespace "z2"
    And I wait 2 seconds for BGP to operate
    Then BGP route in "z2" has "2.2.2.2/32"
    And BGP route in "z2" does not have "1.1.1.1/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
