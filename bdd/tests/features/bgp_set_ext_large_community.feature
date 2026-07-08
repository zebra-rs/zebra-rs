@serial
@bgp_set_ext_large_community
Feature: BGP policy set ext-community and set large-community
  As a network operator
  I want policy-list `set ext-community` and `set large-community`
  actions to stamp the EXT_COMMUNITIES and LARGE_COMMUNITIES attributes
  on routes, so that I can tag routes the same way `set community` tags
  the standard COMMUNITIES attribute.

  Both actions reference a named set (`ext-community-set` /
  `large-community-set`); only the set's exact members contribute
  concrete values (regex members are skipped). `replace` (default)
  overwrites the attribute, `additive` merges, `delete` removes — the
  same {replace|additive|delete} choice as `set community`.

  The set is applied as z2's INBOUND policy so the modified attribute
  lands in z2's own Loc-RIB and is directly observable via
  `show bgp -j`, which now surfaces `community`, `ext_community`, and
  `large_community` fields. Re-evaluation rides the policy-change
  trigger (PolicyRx -> soft-in): applying a config whose policy content
  changed re-runs the inbound policy over the Adj-RIB-In.

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
  ```

  z1 originates 10.0.0.1/32 + 10.0.0.2/32 with no communities. z2
  swaps its inbound policy and we read back the stamped attributes.

  Config files:
  - z1.yaml: AS 65001, advertises 10.0.0.1/32 + 10.0.0.2/32.
  - z2-base.yaml: AS 65002, no input policy; routes carry no communities.
  - z2-set-ext.yaml: `set ext-community RT-SET` (rt:65001:100).
  - z2-set-large.yaml: `set large-community LC-SET` (65001:100:200).
  - z2-set-both.yaml: one entry sets both rt:65002:300 and 65002:400:500.

  Scenario: Setup topology and establish BGP session
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2-base.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z2" has "10.0.0.2/32"

  Scenario: set ext-community stamps the EXT_COMMUNITIES attribute
    Given the test topology exists
    When I apply config "z2-set-ext.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" has "10.0.0.1/32" with "ext_community" value "rt:65001:100"
    And BGP route in "z2" has "10.0.0.2/32" with "ext_community" value "rt:65001:100"

  Scenario: set large-community stamps the LARGE_COMMUNITIES attribute
    Given the test topology exists
    When I apply config "z2-set-large.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" has "10.0.0.1/32" with "large_community" value "65001:100:200"
    And BGP route in "z2" has "10.0.0.2/32" with "large_community" value "65001:100:200"

  Scenario: one entry sets both ext-community and large-community
    Given the test topology exists
    When I apply config "z2-set-both.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" has "10.0.0.1/32" with "ext_community" value "rt:65002:300"
    And BGP route in "z2" has "10.0.0.1/32" with "large_community" value "65002:400:500"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
