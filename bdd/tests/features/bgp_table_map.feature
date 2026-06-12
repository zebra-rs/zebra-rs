@serial
@bgp_table_map
Feature: BGP table-map gates and rewrites RIB installs without touching the Loc-RIB
  As a network operator
  I want `router bgp afi-safi ipv4 table-map <policy>` to filter and
  rewrite BGP best paths at the point they are installed into the
  kernel RIB, while the BGP table itself (and what peers are
  advertised) stays complete — FRR's table-map semantics.

  The exercise: z1 advertises three prefixes. z2 binds table-map TMAP:
  entry 10 denies 1.1.1.1/32, entry 20 permits 2.2.2.2/32 with
  `set med 50` (MED lands in the kernel route metric), entry 30
  permits the rest. All three prefixes must stay visible in z2's BGP
  table throughout; only the kernel routes move. Live policy edits
  must resync the FIB without a session clear, a rebind to a
  nonexistent policy must deny every install (FRR parity), and
  deleting the table-map must restore unfiltered installs.

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
  - z1.yaml: AS 65001, advertises 1.1.1.1/32 + 2.2.2.2/32 + 3.3.3.3/32.
  - z2.yaml: prefix-set DENY = { 1.1.1.1/32 }, MED = { 2.2.2.2/32 };
    policy TMAP = deny DENY / permit MED set med 50 / permit;
    `afi-safi ipv4 table-map TMAP`.
  - z2-deny-more.yaml: DENY = { 1.1.1.1/32, 3.3.3.3/32 } (added).

  Scenario: Setup topology and verify install-time filter and MED rewrite
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP route in "z2" has "1.1.1.1/32"
    And BGP route in "z2" has "2.2.2.2/32"
    And BGP route in "z2" has "3.3.3.3/32"
    And kernel route "1.1.1.1/32" in namespace "z2" should eventually be gone
    And kernel route "2.2.2.2/32" in namespace "z2" should eventually contain "metric 50"
    And kernel route "3.3.3.3/32" in namespace "z2" should eventually contain "192.168.0.1"

  Scenario: Editing the referenced policy resyncs the FIB without a session reset
    Given the test topology exists
    When I apply config "z2-deny-more.yaml" to namespace "z2"
    Then kernel route "3.3.3.3/32" in namespace "z2" should eventually be gone
    And kernel route "2.2.2.2/32" in namespace "z2" should eventually contain "metric 50"
    And BGP route in "z2" has "3.3.3.3/32"

  Scenario: Rebinding to a nonexistent policy denies every install
    Given the test topology exists
    When I apply command "set router bgp afi-safi ipv4 table-map NOSUCH" in namespace "z2"
    Then kernel route "2.2.2.2/32" in namespace "z2" should eventually be gone
    And BGP route in "z2" has "2.2.2.2/32"

  Scenario: Deleting the table-map restores unfiltered installs
    Given the test topology exists
    When I apply command "delete router bgp afi-safi ipv4 table-map NOSUCH" in namespace "z2"
    Then kernel route "1.1.1.1/32" in namespace "z2" should eventually contain "192.168.0.1"
    And kernel route "2.2.2.2/32" in namespace "z2" should eventually contain "192.168.0.1"
    And kernel route "3.3.3.3/32" in namespace "z2" should eventually contain "192.168.0.1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
