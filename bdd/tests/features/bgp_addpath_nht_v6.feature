@serial
@bgp_addpath_nht_v6
Feature: An AddPath neighbor follows the next-hop's reachability (IPv6)
  As a network operator
  I want an AddPath neighbor to lose a path when its next-hop stops
  resolving, and to get it back when the next-hop resolves again
  So the neighbor never forwards on a path we cannot forward on.

  A path whose next-hop does not resolve is not eligible (RFC 4271
  §9.1.2.1). A plain neighbor follows the selection, which leaves such a
  path out. An AddPath neighbor is sent every candidate: the IPv6-unicast
  next-hop re-evaluation re-ran the AddPath loop, which sent the
  unreachable path again, so the AddPath neighbor kept it. IPv6 unicast
  over IPv4 sessions. The IPv4 twin is `bgp_addpath_nht`.

  Test Topology:
  ```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.65.0/24                      │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   h1    │     │   z1    │     │   z2    │     │   z3    │
    │scripted │     │  (DUT)  │     │ AddPath │     │  plain  │
    │ AS65091 │     │ AS65001 │     │ AS65092 │     │ AS65093 │
    │  .2     │     │  .1     │     │  .3     │     │  .4     │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
  ```
  h1 (tests/scripts/bgp_attr_inject_send.py) announces 2001:db8:64:1::/64 with the
  third-party next-hop 2001:db8:64:99::2. z1 resolves it through the static route
  2001:db8:64:99::/64 via h1; deleting that route makes it unreachable,
  adding it back makes it reachable again.

  Config files:
  - z1.yaml: DUT — the static route; eBGP to h1 (passive), AddPath eBGP to
    z2, plain eBGP to z3.
  - z2.yaml: z1's AddPath neighbor. z3.yaml: z1's plain neighbor.

  Scenario: Setup topology; z2 and z3 learn the prefix
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.65.1/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.65.2/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.65.3/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.65.4/24" on bridge "br0"
    And I execute "ip -6 addr add 2001:db8:65::1/64 dev vz1ns" in namespace "z1"
    And I execute "ip -6 addr add 2001:db8:65::2/64 dev vh1ns" in namespace "h1"
    And I execute "ip -6 addr add 2001:db8:65::3/64 dev vz2ns" in namespace "z2"
    And I execute "ip -6 addr add 2001:db8:65::4/64 dev vz3ns" in namespace "z3"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    Then BGP session in "z1" to "192.168.65.3" should eventually be "Established"
    And BGP session in "z1" to "192.168.65.4" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.65.1 65091 192.168.65.2 6 2001:db8:64:99::2 /tmp/bgp_addpath_nht_v6 2001:db8:64:1::/64" in namespace "h1"
    Then BGP session in "z1" to "192.168.65.2" should eventually be "Established"
    And show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:64:1::/64"
    And show command "show bgp ipv6" in namespace "z3" should eventually contain "2001:db8:64:1::/64"

  Scenario: The next-hop stops resolving; both neighbors lose the path
    Given the test topology exists
    When I apply command "delete router static ipv6 route 2001:db8:64:99::/64" in namespace "z1"
    # Control: the plain neighbor follows the selection.
    Then show command "show bgp ipv6" in namespace "z3" should eventually not contain "2001:db8:64:1::/64"
    # Pre-fix the AddPath neighbor kept the path under its path-id.
    And show command "show bgp ipv6" in namespace "z2" should eventually not contain "2001:db8:64:1::/64"
    And BGP session in "z1" to "192.168.65.3" should be "Established"

  Scenario: The next-hop resolves again; both neighbors get the path back
    Given the test topology exists
    When I apply command "set router static ipv6 route 2001:db8:64:99::/64 nexthop 2001:db8:65::2" in namespace "z1"
    Then show command "show bgp ipv6" in namespace "z3" should eventually contain "2001:db8:64:1::/64"
    And show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:64:1::/64"

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
