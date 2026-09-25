@serial
@bgp_addpath_policy_out_v6
Feature: An AddPath neighbor's outbound policy applies to route changes too (IPv6)
  As a network operator
  I want a neighbor's `policy out` to filter and rewrite every IPv6 route
  sent to it with AddPath, not only the ones in the session-up dump
  So a prefix my policy denies never leaks to that neighbor, and my set
  actions are on every UPDATE.

  A neighbor that negotiated AddPath send is not in the plain fan-out, so
  when a route changes its only advertise path is the AddPath loop. For
  IPv6 unicast that loop sent every candidate without running the
  outbound policy: a denied prefix was filtered at session-up and leaked
  on the first change, and a `set` action was missing from every such
  UPDATE. The IPv4 twin (`bgp_addpath_policy_out`) shows the same setup
  already works for IPv4.

  Test Topology:
  ```
  ┌─────────────────────────────────────────────────────────┐
  │                   br0 192.168.59.0/24                   │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │          │   z1    │          │   z2    │
     │scripted │─eBGP────▶│  (DUT)  │─AddPath─▶│ zebra-rs│
     │ AS65061 │          │ AS65001 │  eBGP    │ AS65062 │
     │  .2     │          │  .1     │          │  .3     │
     └─────────┘          └─────────┘          └─────────┘
  ```
  z1 sends IPv6 unicast to z2 with AddPath, through an out-policy that
  denies 2001:db8:58:1::/64 and sets MED 50 on everything else. z1 and z2
  establish first; only then does h1 (tests/scripts/bgp_attr_inject_send.py)
  announce 2001:db8:58:1::/64 and 2001:db8:58:2::/64, so both reach z2
  through the route-change path, not the session-up dump.

  Config files:
  - z1.yaml: DUT — eBGP to h1 (passive); AddPath eBGP to z2 with the
    out-policy; IPv6 unicast over IPv4 sessions.
  - z2.yaml: z1's AddPath neighbor.

  Scenario: Setup topology; z1 and z2 establish before any route exists
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.59.1/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.59.2/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.59.3/24" on bridge "br0"
    And I execute "ip -6 addr add 2001:db8:59::1/64 dev vz1ns" in namespace "z1"
    And I execute "ip -6 addr add 2001:db8:59::2/64 dev vh1ns" in namespace "h1"
    And I execute "ip -6 addr add 2001:db8:59::3/64 dev vz2ns" in namespace "z2"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.59.3" should eventually be "Established"

  Scenario: Routes learned after the session is up go through the out-policy
    Given the test topology exists
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.59.1 65061 192.168.59.2 6 2001:db8:59::2 /tmp/bgp_addpath_policy_out_v6 2001:db8:58:1::/64 2001:db8:58:2::/64" in namespace "h1"
    Then BGP session in "z1" to "192.168.59.2" should eventually be "Established"
    And show command "show bgp ipv6" in namespace "z1" should eventually contain "2001:db8:58:1::/64"
    And show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:58:2::/64"
    # The permitted prefix carries the policy's MED; pre-fix it had none.
    And show command "show bgp ipv6 2001:db8:58:2::/64" in namespace "z2" should contain "metric 50"
    # The denied prefix was announced in the same UPDATE batch as the
    # permitted one; pre-fix it leaked to z2.
    And show command "show bgp ipv6" in namespace "z2" should not contain "2001:db8:58:1::/64"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "h1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
