@serial
@bgp_v6_table_map
Feature: BGP table-map for IPv6 unicast gates RIB installs per address family
  As a network operator
  I want `router bgp afi-safi ipv6 table-map <policy>` to filter and
  rewrite IPv6 best paths at the kernel-install boundary — with the
  same semantics as the IPv4 table-map, and strictly scoped to its
  own address family: a v6 binding must never touch v4 installs.

  The exercise: a single v4 BGP session carries both families
  (ipv4 + ipv6 afi-safi). z1 advertises three v6 prefixes and one v4
  prefix. z2 binds table-map TMAP6 under `afi-safi ipv6` only:
  entry 10 denies 2001:db8:100::/48, entry 20 permits
  2001:db8:200::/48 with `set med 50`, entry 30 permits the rest.
  All three v6 prefixes stay visible in `show bgp ipv6` throughout;
  only the kernel routes move — and the v4 route installs untouched.

  Test Topology:
  ```
  ┌─────────────────┐  192.168.0.0/30   ┌─────────────────┐
  │       z1        │  2001:db8:12::/64 │       z2        │
  │     AS65001     ├───────────────────┤     AS65002     │
  │ .1 / 12::1      │                   │ .2 / 12::2      │
  └─────────────────┘                   └─────────────────┘
  ```

  Config files:
  - z1.yaml: AS 65001, networks 2001:db8:100::/48 + 2001:db8:200::/48
    + 2001:db8:300::/48 (ipv6) and 1.1.1.1/32 (ipv4).
  - z2.yaml: prefix-set DENY6 = { 2001:db8:100::/48 },
    MED6 = { 2001:db8:200::/48 }; policy TMAP6 = deny DENY6 /
    permit MED6 set med 50 / permit; `afi-safi ipv6 table-map TMAP6`;
    ipv4 afi-safi enabled with NO table-map.
  - z2-deny-more.yaml: DENY6 = { 2001:db8:100::/48,
    2001:db8:300::/48 } (added).

  Scenario: Setup topology and verify v6 install filter, MED rewrite, and v4 isolation
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp summary" in namespace "z2" should contain "Established"
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:100::/48"
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:200::/48"
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:300::/48"
    And kernel route "2001:db8:100::/48" in namespace "z2" should eventually be gone
    And kernel route "2001:db8:200::/48" in namespace "z2" should eventually contain "metric 50"
    And kernel route "2001:db8:300::/48" in namespace "z2" should eventually contain "2001:db8:12::1"
    And kernel route "1.1.1.1/32" in namespace "z2" should eventually contain "192.168.0.1"

  Scenario: Editing the referenced policy resyncs the v6 FIB without a session reset
    Given the test topology exists
    When I apply config "z2-deny-more.yaml" to namespace "z2"
    Then kernel route "2001:db8:300::/48" in namespace "z2" should eventually be gone
    And kernel route "2001:db8:200::/48" in namespace "z2" should eventually contain "metric 50"
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:300::/48"

  Scenario: Deleting the v6 table-map restores unfiltered v6 installs
    Given the test topology exists
    When I apply command "delete router bgp afi-safi ipv6 table-map TMAP6" in namespace "z2"
    Then kernel route "2001:db8:100::/48" in namespace "z2" should eventually contain "2001:db8:12::1"
    And kernel route "2001:db8:200::/48" in namespace "z2" should eventually contain "2001:db8:12::1"
    And kernel route "2001:db8:300::/48" in namespace "z2" should eventually contain "2001:db8:12::1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
