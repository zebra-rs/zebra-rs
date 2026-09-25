@serial
@bgp_addpath_soft_out_v6
Feature: An outbound re-sync toward an AddPath neighbor reconciles every path-id (IPv6)
  As a network operator
  I want an out-policy change on an AddPath neighbor to re-evaluate every
  path I sent it, and to withdraw the ones the policy now denies under
  their own path-ids
  So the neighbor ends up holding exactly what the new policy permits.

  An out-policy change (or `clear bgp … soft out`) re-syncs the neighbor
  from the Loc-RIB. The IPv4 twin (`bgp_addpath_soft_out`) pins the IPv4
  unicast re-sync, which read the best path only and withdrew with
  path-id 0; this IPv6 twin is the control — the IPv6 re-sync reconciles
  by path-id already.

  Test Topology:
  ```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.63.0/24                      │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   h1    │     │   h2    │     │   z1    │     │   z2    │
    │scripted │     │scripted │     │  (DUT)  │     │ AddPath │
    │ AS65081 │     │ AS65082 │     │ AS65001 │     │ AS65072 │
    │  .2     │     │  .3     │     │  .1     │     │  .4     │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
  ```
  h1 announces 2001:db8:62:1::/64 with AS_PATH "65081", h2 with "65082 65009
  65010" (tests/scripts/bgp_attr_inject_send.py). z1 sends both paths to
  z2 with AddPath. Then z1's out-policy toward z2 changes twice, each
  followed by a soft-out: first to deny paths whose AS_PATH (as sent, with
  z1's AS) has three or more ASes — h2's path only — then to deny
  everything.

  Config files:
  - z1.yaml: DUT — eBGP to h1 and h2 (passive), AddPath eBGP to z2; IPv6
    unicast over IPv4 sessions.
  - z1-deny-long.yaml: the same with DENY-LONG bound out toward z2.
  - z1-deny-all.yaml: the same with DENY-ALL bound out toward z2.
  - z2.yaml: z1's AddPath neighbor.

  Scenario: Setup topology; z2 holds both paths
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.63.1/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.63.2/24" on bridge "br0"
    And I create namespace "h2" with IP "192.168.63.3/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.63.4/24" on bridge "br0"
    And I execute "ip -6 addr add 2001:db8:63::1/64 dev vz1ns" in namespace "z1"
    And I execute "ip -6 addr add 2001:db8:63::2/64 dev vh1ns" in namespace "h1"
    And I execute "ip -6 addr add 2001:db8:63::3/64 dev vh2ns" in namespace "h2"
    And I execute "ip -6 addr add 2001:db8:63::4/64 dev vz2ns" in namespace "z2"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.63.4" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.63.1 65081 192.168.63.2 6 2001:db8:63::2 /tmp/bgp_addpath_soft_out_v6_h1 2001:db8:62:1::/64" in namespace "h1"
    And I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.63.1 65082 192.168.63.3 6 2001:db8:63::3 /tmp/bgp_addpath_soft_out_v6_h2 2001:db8:62:1::/64@65082,65009,65010" in namespace "h2"
    Then show command "show bgp ipv6 2001:db8:62:1::/64" in namespace "z2" should eventually contain "Paths: (2 available)"

  Scenario: The re-sync withdraws the non-best path the new policy denies
    Given the test topology exists
    When I apply config "z1-deny-long.yaml" to namespace "z1"
    And I run "clear bgp ipv6 neighbor 192.168.63.4 soft out" in namespace "z1"
    Then show command "show bgp ipv6 2001:db8:62:1::/64" in namespace "z2" should eventually contain "Paths: (1 available)"
    And show command "show bgp ipv6 2001:db8:62:1::/64" in namespace "z2" should contain "65001 65081"
    And show command "show bgp ipv6 2001:db8:62:1::/64" in namespace "z2" should not contain "65082"
    And BGP session in "z1" to "192.168.63.4" should be "Established"

  Scenario: The re-sync withdraws the remaining path under its own path-id
    Given the test topology exists
    When I apply config "z1-deny-all.yaml" to namespace "z1"
    And I run "clear bgp ipv6 neighbor 192.168.63.4 soft out" in namespace "z1"
    Then show command "show bgp ipv6" in namespace "z2" should eventually not contain "2001:db8:62:1::/64"
    And BGP session in "z1" to "192.168.63.4" should be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "h1"
    And I delete namespace "h2"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
