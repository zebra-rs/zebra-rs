@serial
@bgp_community_no_export_advertise
Feature: BGP well-known community handling (no-export, no-advertise)
  As a network operator
  I want to verify that the well-known communities NO_EXPORT and
  NO_ADVERTISE are honoured when re-advertising routes across eBGP
  and iBGP sessions, using a three-router topology.

  Test Topology:
  ```
  ┌──────────────────────────────────────────────────────────┐
  │                          br0                             │
  └─────────┬──────────────────┬──────────────────┬──────────┘
            │                  │                  │
       ┌────┴────┐        ┌────┴────┐        ┌────┴────┐
       │   z1    │  eBGP  │   z2    │  iBGP  │   z3    │
       │  (A)    │◀──────▶│  (B)    │◀──────▶│  (C)    │
       │ AS65001 │        │ AS65002 │        │ AS65002 │
       │192.168. │        │192.168. │        │192.168. │
       │  0.1/24 │        │  0.2/24 │        │  0.3/24 │
       └─────────┘        └─────────┘        └─────────┘
  ```

  Config files:
  - z1-1.yaml: A baseline — eBGP peer to B, no network advertised.
  - z1-2.yaml: A advertises 1.1.1.1/32 with no community attribute.
  - z1-3.yaml: A advertises 1.1.1.1/32 with community "no-export".
  - z1-4.yaml: A advertises 1.1.1.1/32 with community "no-advertise".
  - z2-1.yaml: B — eBGP to A, iBGP to C.
  - z3-1.yaml: C — iBGP to B only.

  Convergence wait-time rationale:
  - eBGP MinRouteAdvertisementInterval = 30 s
    (ADV_TIMER_EBGP_SECS in zebra-rs/src/bgp/update_group.rs)
  - iBGP MinRouteAdvertisementInterval =  5 s
    (ADV_TIMER_IBGP_SECS in zebra-rs/src/bgp/update_group.rs)
  - End-to-end A → B → C propagation: up to 30 + 5 = 35 s.
  - Each scenario that triggers a fresh advertisement on A waits
    35 seconds; a session clear before the wait forces an immediate
    re-flood instead of relying on incremental triggers.

  Scenario: Setup topology and establish BGP sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I apply config "z3-1.yaml" to namespace "z3"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z2" to "192.168.0.3" should be "Established"
    And BGP session in "z3" to "192.168.0.2" should be "Established"

  Scenario: A advertises 1.1.1.1/32 with no community — C receives it
    Given the test topology exists
    When I apply config "z1-2.yaml" to namespace "z1"
    And I wait 35 seconds for BGP to operate
    Then BGP route in "z2" has "1.1.1.1/32"
    And BGP route in "z3" has "1.1.1.1/32"

  Scenario: A re-advertises 1.1.1.1/32 with community no-export — C still receives it
    Given the test topology exists
    When I apply config "z1-3.yaml" to namespace "z1"
    And I clear namespace "z1" neighbor "192.168.0.2"
    And I wait 35 seconds for BGP to operate
    Then BGP route in "z2" has "1.1.1.1/32"
    And BGP route in "z3" has "1.1.1.1/32"

  Scenario: A re-advertises 1.1.1.1/32 with community no-advertise — C does NOT receive it
    Given the test topology exists
    When I apply config "z1-4.yaml" to namespace "z1"
    And I clear namespace "z1" neighbor "192.168.0.2"
    And I wait 35 seconds for BGP to operate
    Then BGP route in "z2" has "1.1.1.1/32"
    And BGP route in "z3" does not have "1.1.1.1/32"

  Scenario: A reverts to plain advertisement — C receives it again
    Given the test topology exists
    When I apply config "z1-2.yaml" to namespace "z1"
    And I clear namespace "z1" neighbor "192.168.0.2"
    And I wait 35 seconds for BGP to operate
    Then BGP route in "z2" has "1.1.1.1/32"
    And BGP route in "z3" has "1.1.1.1/32"

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
