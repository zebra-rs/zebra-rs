@serial
@bgp_as_path_match
Feature: BGP match as-path-set with FRR-compatible regular expressions
  As a network operator
  I want zebra-rs `match as-path` to accept the same AS-path regular
  expressions as FRR's `bgp as-path access-list`, so that policies port
  between the two routers unchanged.

  The AS-path regex engine mirrors FRR's `bgp_regcomp`
  (bgpd/bgp_regex.c): the `_` magic character expands to
  `(^|[,{}() ]|$)`, matching a separator, the start, or the end of the
  path. Regexes run against the AS_PATH rendered exactly like FRR's
  `aspath->str` (space-separated ASNs; AS_SET members comma-separated).
  This feature exercises exact anchored matching plus the three classic
  `_` idioms — neighbor-is (`^ASN_`), originates-from (`_ASN$`), and
  transits (`_ASN_`).

  Test Topology (linear eBGP chain, all on one L2 segment):
  ```
  ┌──────────────────────────────────────────────────┐
  │                        br0                        │
  └───────┬───────────────┬───────────────┬───────────┘
          │               │               │
     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
     │   z1    │────▶│   z2    │────▶│   z3    │
     │ AS65001 │     │ AS65002 │     │ AS65003 │
     │ .0.1/24 │     │ .0.2/24 │     │ .0.3/24 │
     └─────────┘     └─────────┘     └─────────┘
  ```

  z1 originates 10.0.0.1/32 + 10.0.0.2/32 and peers only z2. z2 is a
  transit AS with no policy, peering z1 and z3. z3 peers only z2, so the
  two prefixes reach z3 with AS_PATH `65002 65001`. Each scenario swaps
  z3's inbound policy and asserts which prefixes survive in z3's RIB.
  Re-evaluation rides the policy-change trigger (PolicyRx -> soft-in):
  applying a config whose as-path-set/policy changed re-runs the inbound
  policy over the Adj-RIB-In — no `clear` needed.

  Config files:
  - z1.yaml: AS 65001, advertises 10.0.0.1/32 + 10.0.0.2/32 to z2.
  - z2.yaml: AS 65002, transit; peers z1 and z3, no policy.
  - z3-base.yaml: AS 65003, no input policy; both prefixes accepted.
  - z3-exact-pass.yaml: `^65002 65001$` — exact whole-path match.
  - z3-exact-fail.yaml: `^65001 65002$` — right ASNs, wrong order.
  - z3-origin-pass.yaml: `_65001$` — originated by 65001.
  - z3-origin-fail.yaml: `_65003$` — 65003 is not on the received path.
  - z3-neighbor-pass.yaml: `^65002_` — leftmost (neighbor) AS is 65002.
  - z3-transit-fail.yaml: `_65099_` — 65099 is nowhere in the path.

  Scenario: Setup topology and establish the eBGP chain
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3-base.yaml" to namespace "z3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z2" to "192.168.0.3" should be "Established"
    And BGP session in "z3" to "192.168.0.2" should be "Established"
    And BGP route in "z3" has "10.0.0.1/32"
    And BGP route in "z3" has "10.0.0.2/32"

  Scenario: exact match accepts the whole AS_PATH anchored with ^ and $
    Given the test topology exists
    When I apply config "z3-exact-pass.yaml" to namespace "z3"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z3" has "10.0.0.1/32"
    And BGP route in "z3" has "10.0.0.2/32"

  Scenario: exact match rejects the same ASNs in the wrong order
    Given the test topology exists
    When I apply config "z3-exact-fail.yaml" to namespace "z3"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z3" does not have "10.0.0.1/32"
    And BGP route in "z3" does not have "10.0.0.2/32"

  Scenario: _ASN$ accepts routes originated by that AS
    Given the test topology exists
    When I apply config "z3-origin-pass.yaml" to namespace "z3"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z3" has "10.0.0.1/32"
    And BGP route in "z3" has "10.0.0.2/32"

  Scenario: _ASN$ rejects routes not originated by that AS
    Given the test topology exists
    When I apply config "z3-origin-fail.yaml" to namespace "z3"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z3" does not have "10.0.0.1/32"
    And BGP route in "z3" does not have "10.0.0.2/32"

  Scenario: ^ASN_ accepts routes whose neighbor (leftmost) AS matches
    Given the test topology exists
    When I apply config "z3-neighbor-pass.yaml" to namespace "z3"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z3" has "10.0.0.1/32"
    And BGP route in "z3" has "10.0.0.2/32"

  Scenario: _ASN_ rejects routes that do not transit that AS
    Given the test topology exists
    When I apply config "z3-transit-fail.yaml" to namespace "z3"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z3" does not have "10.0.0.1/32"
    And BGP route in "z3" does not have "10.0.0.2/32"

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
