@serial
@bgp_addpath_nht
Feature: An AddPath neighbor follows the next-hop's reachability (IPv4)
  As a network operator
  I want an AddPath neighbor to lose a path when its next-hop stops
  resolving, and to get it back when the next-hop resolves again
  So the neighbor never forwards on a path we cannot forward on.

  A path whose next-hop does not resolve is not eligible (RFC 4271
  §9.1.2.1). A plain neighbor follows the selection, which leaves such a
  path out. An AddPath neighbor is sent every candidate, and the
  next-hop re-evaluation ran only the plain fan-out for IPv4 unicast: the
  AddPath neighbor kept the path after its next-hop stopped resolving.
  The IPv6 twin is `bgp_addpath_nht_v6`; `bgp_shard_addpath_nht` runs
  this with a sharded RIB.

  Test Topology:
  ```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.64.0/24                      │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   h1    │     │   z1    │     │   z2    │     │   z3    │
    │scripted │     │  (DUT)  │     │ AddPath │     │  plain  │
    │ AS65091 │     │ AS65001 │     │ AS65092 │     │ AS65093 │
    │  .2     │     │  .1     │     │  .3     │     │  .4     │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
  ```
  h1 (tests/scripts/bgp_attr_inject_send.py) announces 10.64.1.0/24 with the
  third-party next-hop 10.64.99.2. z1 resolves it through the static route
  10.64.99.0/24 via h1; deleting that route makes it unreachable,
  adding it back makes it reachable again.

  Config files:
  - z1.yaml: DUT — the static route; eBGP to h1 (passive), AddPath eBGP to
    z2, plain eBGP to z3.
  - z2.yaml: z1's AddPath neighbor. z3.yaml: z1's plain neighbor.

  Scenario: Setup topology; z2 and z3 learn the prefix
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.64.1/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.64.2/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.64.3/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.64.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    Then BGP session in "z1" to "192.168.64.3" should eventually be "Established"
    And BGP session in "z1" to "192.168.64.4" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.64.1 65091 192.168.64.2 4 10.64.99.2 /tmp/bgp_addpath_nht 10.64.1.0/24" in namespace "h1"
    Then BGP session in "z1" to "192.168.64.2" should eventually be "Established"
    And show command "show bgp" in namespace "z2" should eventually contain "10.64.1.0/24"
    And show command "show bgp" in namespace "z3" should eventually contain "10.64.1.0/24"

  Scenario: The next-hop stops resolving; both neighbors lose the path
    Given the test topology exists
    When I apply command "delete router static ipv4 route 10.64.99.0/24" in namespace "z1"
    # Control: the plain neighbor follows the selection.
    Then show command "show bgp" in namespace "z3" should eventually not contain "10.64.1.0/24"
    # Pre-fix the AddPath neighbor kept the path under its path-id.
    And show command "show bgp" in namespace "z2" should eventually not contain "10.64.1.0/24"
    And BGP session in "z1" to "192.168.64.3" should be "Established"

  Scenario: The next-hop resolves again; both neighbors get the path back
    Given the test topology exists
    When I apply command "set router static ipv4 route 10.64.99.0/24 nexthop 192.168.64.2" in namespace "z1"
    Then show command "show bgp" in namespace "z3" should eventually contain "10.64.1.0/24"
    And show command "show bgp" in namespace "z2" should eventually contain "10.64.1.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "h1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
