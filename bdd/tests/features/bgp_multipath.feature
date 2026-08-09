@serial
@bgp_multipath
Feature: BGP multipath (maximum-paths)
  As a network operator
  I want equal-cost eBGP paths installed together as one ECMP route
  So that a leaf with several upstreams load-shares instead of pinning
  all traffic to a single link.

  Test Topology:
  ```
  ┌─────────────────────────────────────────────────────────┐
  │                          br0                            │
  └───────────┬───────────────┬───────────────┬─────────────┘
              │               │               │
         ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
         │   z1    │     │   z2    │     │   z3    │
         │ AS65001 │     │ AS65002 │     │ AS65002 │
         │  (DUT)  │     │         │     │         │
         │192.168. │     │192.168. │     │192.168. │
         │  0.1/24 │     │  0.2/24 │     │  0.3/24 │
         └─────────┘     └─────────┘     └─────────┘
  ```

  z2 and z3 share AS 65002 and both advertise 10.99.0.0/24, so the two
  paths z1 learns tie on every best-path comparison down to the
  router-id tie-break — the multipath-eligible case. z1 runs
  "maximum-paths 4" for ipv4 from the start.

  Config files:
  - z1-1.yaml: AS 65001, peers to z2/z3, afi-safi ipv4 maximum-paths 4
  - z2-1.yaml: AS 65002, network 10.99.0.0/24 (z2-2.yaml withdraws it)
  - z3-1.yaml: AS 65002, network 10.99.0.0/24
  - z3-2.yaml: same as z3-1 but AS 65003 (for the strict/relax split)

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
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Established"
    And BGP session in "z1" to "192.168.0.3" should eventually be "Established"

  Scenario: Two equal-cost paths install as one ECMP route
    Given the test topology exists
    Then kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "nexthop via 192.168.0.2"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "nexthop via 192.168.0.3"
    And show command "show bgp" in namespace "z1" should eventually contain "*="

  Scenario: Withdrawing one upstream leaves the other leg installed
    Given the test topology exists
    When I apply config "z2-2.yaml" to namespace "z2"
    Then kernel route "10.99.0.0/24" in namespace "z1" should eventually not contain "192.168.0.2"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "via 192.168.0.3"
    And BGP route in "z1" has "10.99.0.0/24"

  Scenario: Re-advertising restores the second leg
    Given the test topology exists
    When I apply config "z2-1.yaml" to namespace "z2"
    Then kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "nexthop via 192.168.0.2"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "nexthop via 192.168.0.3"

  Scenario: Lowering maximum-paths at runtime withdraws the surplus leg
    Given the test topology exists
    When I apply command "set router bgp afi-safi ipv4 maximum-paths 1" in namespace "z1"
    Then kernel route "10.99.0.0/24" in namespace "z1" should eventually not contain "nexthop via"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "via 192.168.0.2"

  Scenario: Raising maximum-paths rediscovers the second leg
    Given the test topology exists
    When I apply command "set router bgp afi-safi ipv4 maximum-paths 4" in namespace "z1"
    Then kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "nexthop via 192.168.0.2"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "nexthop via 192.168.0.3"

  Scenario: Strict default does not load-share across two upstream ASes
    Given the test topology exists
    # The global AS cannot change on a live instance, so z3 restarts to
    # come back as AS 65003; the restart also bounces z1's peer, which
    # must purge the old AS-65002 path.
    When I stop zebra-rs in namespace "z3"
    And I apply command "set router bgp neighbor 192.168.0.3 remote-as 65003" in namespace "z1"
    And I start zebra-rs in namespace "z3"
    And I apply config "z3-2.yaml" to namespace "z3"
    Then BGP session in "z1" to "192.168.0.3" should eventually be "Established"
    And show command "show bgp" in namespace "z1" should eventually contain "65003"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually not contain "nexthop via"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "via 192.168.0.2"

  Scenario: multipath-relax admits equal-length paths across ASes
    Given the test topology exists
    When I apply command "set router bgp afi-safi ipv4 bestpath as-path multipath-relax true" in namespace "z1"
    Then kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "nexthop via 192.168.0.2"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "nexthop via 192.168.0.3"

  Scenario: maximum-paths-ibgp is accepted and leaves eBGP sets alone
    Given the test topology exists
    When I apply command "set router bgp afi-safi ipv4 maximum-paths-ibgp 2" in namespace "z1"
    Then kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "nexthop via 192.168.0.2"
    And kernel route "10.99.0.0/24" in namespace "z1" should eventually contain "nexthop via 192.168.0.3"

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
