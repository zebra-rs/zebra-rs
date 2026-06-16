@serial
@bgp_community
Feature: BGP well-known community handling (no-export, no-advertise)
  As a network operator
  I want to verify that the well-known communities NO_EXPORT and
  NO_ADVERTISE are honoured when re-advertising routes across eBGP
  and iBGP sessions, using a four-router topology.

  Test Topology:
  ```
  ┌────────────────────────────────────────────────────────────────────────┐
  │                                  br0                                   │
  └────────┬──────────────────┬──────────────────┬──────────────────┬─────┘
           │                  │                  │                  │
      ┌────┴────┐        ┌────┴────┐        ┌────┴────┐        ┌────┴────┐
      │   z1    │  eBGP  │   z2    │  iBGP  │   z3    │        │   z4    │
      │  (A)    │◀──────▶│  (B)    │◀──────▶│  (C)    │        │  (D)    │
      │ AS65001 │        │ AS65002 │        │ AS65002 │        │ AS65003 │
      │192.168. │        │192.168. │        │192.168. │        │192.168. │
      │  0.1/24 │        │  0.2/24 │        │  0.3/24 │        │  0.4/24 │
      └─────────┘        └────┬────┘        └─────────┘        └────┬────┘
                              │                eBGP                 │
                              └─────────────────────────────────────┘
  ```
  B has an iBGP peer (C, same AS) and an eBGP peer (D, AS65003), so a
  route from A exercises both re-advertisement edges:
  - NO_EXPORT: B keeps advertising to C (iBGP) but must NOT export to
    D (eBGP) — RFC 1997.
  - NO_ADVERTISE: B must advertise to neither C nor D.

  Config files:
  - z1-1.yaml: A baseline — eBGP peer to B, no network advertised.
  - z1-2.yaml: A advertises 1.1.1.1/32 with no community attribute.
  - z1-3.yaml: A advertises 1.1.1.1/32 with community "no-export".
  - z1-4.yaml: A advertises 1.1.1.1/32 with community "no-advertise".
  - z1-5.yaml: A advertises 1.1.1.1/32 through a permit-all policy
    (config apply is additive, so reverting means OVERWRITING the
    neighbor's `policy out` leaf with a community-free policy — the
    no-community z1-2.yaml cannot remove an already-set leaf).
  - z2-1.yaml: B — eBGP to A, iBGP to C, eBGP to D.
  - z3-1.yaml: C — iBGP to B only.
  - z4-1.yaml: D — eBGP to B only.

  Convergence wait-time rationale:
  - Every router sets `timer adv-interval ebgp: 3`, overriding the
    30 s default eBGP MinRouteAdvertisementInterval so the two-hop eBGP
    path does not dominate the run. (iBGP keeps its 5 s default.)
  - End-to-end A → B → C propagation: up to 3 + 5 =  8 s.
  - End-to-end A → B → D propagation: up to 3 + 3 =  6 s.
  - Each scenario that triggers a fresh advertisement on A waits
    20 seconds (the slowest path plus a wide margin); a session clear
    before the wait forces an immediate re-flood instead of relying on
    incremental triggers. The previous 30 s timer / 65 s wait left only
    a 5 s margin on the 60 s eBGP path, which made the D-receives
    assertions flaky under load.

  Scenario: Setup topology and establish BGP sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.0.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I apply config "z3-1.yaml" to namespace "z3"
    And I apply config "z4-1.yaml" to namespace "z4"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z2" to "192.168.0.3" should be "Established"
    And BGP session in "z3" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.4" should be "Established"
    And BGP session in "z4" to "192.168.0.2" should be "Established"

  Scenario: A advertises 1.1.1.1/32 with no community — C and D receive it
    Given the test topology exists
    When I apply config "z1-2.yaml" to namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP route in "z2" has "1.1.1.1/32"
    And BGP route in "z3" has "1.1.1.1/32"
    And BGP route in "z4" has "1.1.1.1/32"

  Scenario: A re-advertises 1.1.1.1/32 with community no-export — C still receives it, D does NOT
    Given the test topology exists
    When I apply config "z1-3.yaml" to namespace "z1"
    And I clear namespace "z1" neighbor "192.168.0.2"
    And I wait 20 seconds for BGP to operate
    Then BGP route in "z2" has "1.1.1.1/32"
    And BGP route in "z3" has "1.1.1.1/32"
    And BGP route in "z4" does not have "1.1.1.1/32"

  Scenario: A re-advertises 1.1.1.1/32 with community no-advertise — neither C nor D receives it
    Given the test topology exists
    When I apply config "z1-4.yaml" to namespace "z1"
    And I clear namespace "z1" neighbor "192.168.0.2"
    And I wait 20 seconds for BGP to operate
    Then BGP route in "z2" has "1.1.1.1/32"
    And BGP route in "z3" does not have "1.1.1.1/32"
    And BGP route in "z4" does not have "1.1.1.1/32"

  Scenario: A reverts to a community-free advertisement — C and D receive it again
    Given the test topology exists
    When I apply config "z1-5.yaml" to namespace "z1"
    And I clear namespace "z1" neighbor "192.168.0.2"
    And I wait 20 seconds for BGP to operate
    Then BGP route in "z2" has "1.1.1.1/32"
    And BGP route in "z3" has "1.1.1.1/32"
    And BGP route in "z4" has "1.1.1.1/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "z4"
    And I delete bridge "br0"
    Then the test environment should be clean
