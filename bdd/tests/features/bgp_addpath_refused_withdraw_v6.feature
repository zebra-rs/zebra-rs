@serial
@bgp_addpath_refused_withdraw_v6
Feature: An AddPath path replaced by one the egress refuses is withdrawn (IPv6)
  As a network operator
  I want an AddPath neighbor to lose a path when its replacement may not
  be advertised — NO_ADVERTISE, an out-policy deny, an LLGR-stale path
  toward a non-LLGR neighbor
  So the neighbor does not keep forwarding on the old path forever.

  When a path an AddPath neighbor holds is replaced, the replacement goes
  out under the same path-id. If the egress refuses the replacement, the
  path-id must be withdrawn. The IPv4 twin (`bgp_addpath_refused_withdraw`)
  pins IPv4 unicast, whose AddPath loop only skipped it; this IPv6 twin
  is the control — the IPv6-unicast AddPath loop diffs the Adj-RIB-Out
  and withdraws the path-id already.

  Test Topology:
  ```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.61.0/24                      │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   h1    │     │   z1    │     │   z2    │     │   z3    │
    │scripted │     │  (DUT)  │     │ AddPath │     │  plain  │
    │ AS65071 │     │ AS65001 │     │ AS65072 │     │ AS65073 │
    │  .2     │     │  .1     │     │  .3     │     │  .4     │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
  ```
  h1 runs tests/scripts/bgp_attr_inject_send.py and announces 2001:db8:60:1::/64
  at session-up. On the trigger file /tmp/bgp_addpath_refused_withdraw_v6.go
  it re-announces 2001:db8:60:1::/64 with the NO_ADVERTISE community and, in the
  same write, the control prefix 2001:db8:60:2::/64. z1 must advertise
  2001:db8:60:1::/64 to nobody after that.

  Config files:
  - z1.yaml: DUT — eBGP to h1 (passive), AddPath eBGP to z2, plain eBGP to z3;
    IPv6 unicast over IPv4 sessions.
  - z2.yaml: z1's AddPath neighbor. z3.yaml: z1's plain neighbor.

  Scenario: Setup topology; z2 and z3 learn the prefix
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.61.1/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.61.2/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.61.3/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.61.4/24" on bridge "br0"
    And I execute "ip -6 addr add 2001:db8:61::1/64 dev vz1ns" in namespace "z1"
    And I execute "ip -6 addr add 2001:db8:61::2/64 dev vh1ns" in namespace "h1"
    And I execute "ip -6 addr add 2001:db8:61::3/64 dev vz2ns" in namespace "z2"
    And I execute "ip -6 addr add 2001:db8:61::4/64 dev vz3ns" in namespace "z3"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    Then BGP session in "z1" to "192.168.61.3" should eventually be "Established"
    And BGP session in "z1" to "192.168.61.4" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.61.1 65071 192.168.61.2 6 2001:db8:61::2 /tmp/bgp_addpath_refused_withdraw_v6 2001:db8:60:1::/64 -- 2001:db8:60:1::/64=c0:08:ffffff02 2001:db8:60:2::/64" in namespace "h1"
    Then BGP session in "z1" to "192.168.61.2" should eventually be "Established"
    And show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:60:1::/64"
    And show command "show bgp ipv6" in namespace "z3" should eventually contain "2001:db8:60:1::/64"

  Scenario: The NO_ADVERTISE replacement withdraws the path from both neighbors
    Given the test topology exists
    When I execute "touch /tmp/bgp_addpath_refused_withdraw_v6.go" in namespace "h1"
    # The control prefix came in the same write, after the replacement.
    Then show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:60:2::/64"
    And show command "show bgp ipv6" in namespace "z3" should eventually contain "2001:db8:60:2::/64"
    # Control: the plain neighbor lost it.
    And show command "show bgp ipv6" in namespace "z3" should eventually not contain "2001:db8:60:1::/64"
    # The AddPath neighbor lost it too.
    And show command "show bgp ipv6" in namespace "z2" should eventually not contain "2001:db8:60:1::/64"

  Scenario: Teardown topology
    Given the test topology exists
    When I execute "rm -f /tmp/bgp_addpath_refused_withdraw_v6.go" in namespace "h1"
    And I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "h1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
