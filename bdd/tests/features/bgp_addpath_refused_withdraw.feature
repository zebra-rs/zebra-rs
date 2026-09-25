@serial
@bgp_addpath_refused_withdraw
Feature: An AddPath path replaced by one the egress refuses is withdrawn (IPv4)
  As a network operator
  I want an AddPath neighbor to lose a path when its replacement may not
  be advertised — NO_ADVERTISE, an out-policy deny, an LLGR-stale path
  toward a non-LLGR neighbor
  So the neighbor does not keep forwarding on the old path forever.

  When a path an AddPath neighbor holds is replaced, the replacement goes
  out under the same path-id. If the egress refuses the replacement, the
  path-id must be withdrawn. For IPv4 unicast, VPNv4 and VPNv6 the AddPath
  loop only skipped it, so the neighbor kept the old path. A plain
  neighbor gets the withdraw; this feature puts both side by side. The
  IPv6 twin (`bgp_addpath_refused_withdraw_v6`) is the control: its
  AddPath loop diffs the Adj-RIB-Out and withdraws already.

  Test Topology:
  ```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.60.0/24                      │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   h1    │     │   z1    │     │   z2    │     │   z3    │
    │scripted │     │  (DUT)  │     │ AddPath │     │  plain  │
    │ AS65071 │     │ AS65001 │     │ AS65072 │     │ AS65073 │
    │  .2     │     │  .1     │     │  .3     │     │  .4     │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
  ```
  h1 runs tests/scripts/bgp_attr_inject_send.py and announces 10.60.1.0/24
  at session-up. On the trigger file /tmp/bgp_addpath_refused_withdraw.go
  it re-announces 10.60.1.0/24 with the NO_ADVERTISE community and, in the
  same write, the control prefix 10.60.2.0/24. z1 must advertise
  10.60.1.0/24 to nobody after that.

  Config files:
  - z1.yaml: DUT — eBGP to h1 (passive), AddPath eBGP to z2, plain eBGP to z3.
  - z2.yaml: z1's AddPath neighbor. z3.yaml: z1's plain neighbor.

  Scenario: Setup topology; z2 and z3 learn the prefix
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.60.1/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.60.2/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.60.3/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.60.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    Then BGP session in "z1" to "192.168.60.3" should eventually be "Established"
    And BGP session in "z1" to "192.168.60.4" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.60.1 65071 192.168.60.2 4 192.168.60.2 /tmp/bgp_addpath_refused_withdraw 10.60.1.0/24 -- 10.60.1.0/24=c0:08:ffffff02 10.60.2.0/24" in namespace "h1"
    Then BGP session in "z1" to "192.168.60.2" should eventually be "Established"
    And show command "show bgp" in namespace "z2" should eventually contain "10.60.1.0/24"
    And show command "show bgp" in namespace "z3" should eventually contain "10.60.1.0/24"

  Scenario: The NO_ADVERTISE replacement withdraws the path from both neighbors
    Given the test topology exists
    When I execute "touch /tmp/bgp_addpath_refused_withdraw.go" in namespace "h1"
    # The control prefix came in the same write, after the replacement.
    Then show command "show bgp" in namespace "z2" should eventually contain "10.60.2.0/24"
    And show command "show bgp" in namespace "z3" should eventually contain "10.60.2.0/24"
    # Control: the plain neighbor lost it.
    And show command "show bgp" in namespace "z3" should eventually not contain "10.60.1.0/24"
    # Pre-fix the AddPath neighbor kept the old path under its path-id.
    And show command "show bgp" in namespace "z2" should eventually not contain "10.60.1.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I execute "rm -f /tmp/bgp_addpath_refused_withdraw.go" in namespace "h1"
    And I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "h1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
