@serial
@bgp_addpath_policy_out
Feature: An AddPath neighbor's outbound policy applies to route changes too (IPv4)
  As a network operator
  I want a neighbor's `policy out` to filter and rewrite every IPv4 route
  sent to it with AddPath, not only the ones in the session-up dump
  So a prefix my policy denies never leaks to that neighbor, and my set
  actions are on every UPDATE.

  A neighbor that negotiated AddPath send is not in the plain fan-out, so
  when a route changes its only advertise path is the AddPath loop. The
  IPv6 twin (`bgp_addpath_policy_out_v6`) pins the IPv6-unicast loop,
  which skipped the outbound policy; this IPv4 twin is its control — the
  IPv4 AddPath path applies the policy already.

  Test Topology:
  ```
  ┌─────────────────────────────────────────────────────────┐
  │                   br0 192.168.58.0/24                   │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │          │   z1    │          │   z2    │
     │scripted │─eBGP────▶│  (DUT)  │─AddPath─▶│ zebra-rs│
     │ AS65061 │          │ AS65001 │  eBGP    │ AS65062 │
     │  .2     │          │  .1     │          │  .3     │
     └─────────┘          └─────────┘          └─────────┘
  ```
  z1 sends IPv4 unicast to z2 with AddPath, through an out-policy that
  denies 10.58.1.0/24 and sets MED 50 on everything else. z1 and z2
  establish first; only then does h1 (tests/scripts/bgp_attr_inject_send.py)
  announce 10.58.1.0/24 and 10.58.2.0/24, so both reach z2
  through the route-change path, not the session-up dump.

  Config files:
  - z1.yaml: DUT — eBGP to h1 (passive); AddPath eBGP to z2 with the
    out-policy.
  - z2.yaml: z1's AddPath neighbor.

  Scenario: Setup topology; z1 and z2 establish before any route exists
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.58.1/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.58.2/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.58.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.58.3" should eventually be "Established"

  Scenario: Routes learned after the session is up go through the out-policy
    Given the test topology exists
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.58.1 65061 192.168.58.2 4 192.168.58.2 /tmp/bgp_addpath_policy_out 10.58.1.0/24 10.58.2.0/24" in namespace "h1"
    Then BGP session in "z1" to "192.168.58.2" should eventually be "Established"
    And show command "show bgp" in namespace "z1" should eventually contain "10.58.1.0/24"
    And show command "show bgp" in namespace "z2" should eventually contain "10.58.2.0/24"
    # The permitted prefix carries the policy's MED.
    And show command "show bgp 10.58.2.0/24" in namespace "z2" should contain "metric 50"
    # The denied prefix was announced in the same UPDATE batch as the
    # permitted one.
    And show command "show bgp" in namespace "z2" should not contain "10.58.1.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "h1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
