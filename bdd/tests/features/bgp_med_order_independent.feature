@serial
@bgp_med_order_independent
Feature: The best path does not depend on the order paths arrived in, with MED in play (IPv4)
  As a network operator
  I want best-path selection to give one answer for one set of paths
  So neither the order my neighbors' routes arrived in nor an unchanged
  re-advertisement moves my best path, my FIB and my advertisements.

  MED is compared only between paths from the same neighboring AS, so the
  pairwise comparison is not transitive. zebra-rs picked the winner with
  one linear pass over the candidate list, so the answer depended on the
  list's order — and a replaced path moves to the tail of that list, so
  re-advertising an unchanged path could change the winner. Deterministic
  MED settles it: pick the best path within each neighboring AS first
  (MED applies), then compare those (MED does not).

  Test Topology:
  ```
    ┌──────────────────────────────────────────────────────────┐
    │                   br0 192.168.54.0/24                    │
    └─────┬───────────┬───────────┬───────────┬───────────┬────┘
     ┌────┴───┐  ┌────┴───┐  ┌────┴───┐  ┌────┴───┐  ┌────┴───┐
     │   h1   │  │   h2   │  │   h3   │  │   z1   │  │   z2   │
     │   A    │  │   B    │  │   C    │  │ (DUT)  │  │        │
     │AS65081 │  │AS65082 │  │AS65081 │  │AS65001 │  │AS65090 │
     │ MED 10 │  │ no MED │  │ MED 5  │  │        │  │        │
     │   .2   │  │   .3   │  │   .4   │  │   .1   │  │   .5   │
     └────────┘  └────────┘  └────────┘  └────────┘  └────────┘
  ```
  h1, h2 and h3 run tests/scripts/bgp_attr_inject_send.py and announce
  10.54.0.0/24, each with the same AS_PATH length and its own community:
  A = 65081:1 (MED 10), B = 65082:2 (no MED), C = 65081:3 (MED 5). Their
  BGP Identifiers order A < B < C. Deterministic MED: C beats A on MED
  (same neighboring AS), then B beats C on BGP Identifier — B is the best
  path. The paths arrive in the order A, B, C, for which the linear pass
  chose C. On the trigger file /tmp/bgp_med_order_independent.go, h1
  re-announces A unchanged plus the control prefix 10.54.1.0/24; the
  linear pass then chose A. z2 shows which path z1 selected.

  Config files:
  - z1.yaml: DUT — eBGP to h1, h2, h3 (passive) and to z2.
  - z2.yaml: z1's downstream eBGP neighbor.

  Scenario: Setup topology; the three paths arrive in the order A, B, C
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.54.1/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.54.2/24" on bridge "br0"
    And I create namespace "h2" with IP "192.168.54.3/24" on bridge "br0"
    And I create namespace "h3" with IP "192.168.54.4/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.54.5/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.54.5" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.54.1 65081 192.168.54.2 4 192.168.54.2 /tmp/bgp_med_order_independent 10.54.0.0/24=80:04:0000000a+c0:08:fe390001 -- 10.54.0.0/24=80:04:0000000a+c0:08:fe390001 10.54.1.0/24=c0:08:fe390001" in namespace "h1"
    Then show command "show bgp 10.54.0.0/24" in namespace "z1" should eventually contain "Paths: (1 available)"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.54.1 65082 192.168.54.3 4 192.168.54.3 /tmp/bgp_med_order_independent_h2 10.54.0.0/24=c0:08:fe3a0002" in namespace "h2"
    Then show command "show bgp 10.54.0.0/24" in namespace "z1" should eventually contain "Paths: (2 available)"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.54.1 65081 192.168.54.4 4 192.168.54.4 /tmp/bgp_med_order_independent_h3 10.54.0.0/24=80:04:00000005+c0:08:fe390003" in namespace "h3"
    Then show command "show bgp 10.54.0.0/24" in namespace "z1" should eventually contain "Paths: (3 available)"

  Scenario: z1 selects B, the deterministic-MED best path
    Given the test topology exists
    # Pre-fix the linear pass over [A, B, C] chose C (A vs B: B's
    # Identifier loses; A vs C: C's MED wins).
    Then show command "show bgp 10.54.0.0/24" in namespace "z2" should eventually contain "Community: 65082:2"
    And show command "show bgp 10.54.0.0/24" in namespace "z2" should not contain "65081:3"

  Scenario: An unchanged re-advertisement does not move the best path
    Given the test topology exists
    When I execute "touch /tmp/bgp_med_order_independent.go" in namespace "h1"
    # The control prefix came in the same write as A's unchanged
    # re-advertisement; once z2 has it, z1 has processed both.
    Then show command "show bgp" in namespace "z2" should eventually contain "10.54.1.0/24"
    And I wait 3 seconds
    # Pre-fix A moved to the tail of the candidate list and the linear
    # pass over [B, C, A] chose A.
    And show command "show bgp 10.54.0.0/24" in namespace "z2" should contain "Community: 65082:2"
    And show command "show bgp 10.54.0.0/24" in namespace "z2" should not contain "65081:1"

  Scenario: Teardown topology
    Given the test topology exists
    When I execute "rm -f /tmp/bgp_med_order_independent.go" in namespace "h1"
    And I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "h1"
    And I delete namespace "h2"
    And I delete namespace "h3"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
