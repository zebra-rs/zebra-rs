@serial
@bgp_inbound_loop_withdraw
Feature: A looped replacement withdraws the neighbor's earlier path (IPv4)
  As a network operator
  I want an UPDATE that my AS-path loop check rejects to still withdraw
  the path that neighbor sent before for the same prefix
  So a neighbor that re-routes through me after losing its own path does
  not leave me forwarding to it while it forwards back.

  An UPDATE replaces the path its sender advertised before for the same
  NLRI (RFC 4271 §3.1). When the replacement carries our AS it is
  unusable (RFC 4271 §9.1.2), but the old path is gone too: the neighbor
  no longer has it. FRR removes the existing path when it filters the
  replacement. zebra-rs dropped the UPDATE and kept the old path, so it
  kept routing to the neighbor — which now routes through us — and kept
  advertising the path downstream. Neighbors such as FRR send a looped
  path back by default, so this needs nothing unusual to happen.

  Test Topology:
  ```
  ┌─────────────────────────────────────────────────────────┐
  │                   br0 192.168.48.0/24                   │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │          │   z1    │          │   z2    │
     │scripted │─eBGP────▶│  (DUT)  │─eBGP────▶│ zebra-rs│
     │ AS65061 │          │ AS65060 │          │ AS65062 │
     │  .2     │          │  .1     │          │  .3     │
     └─────────┘          └─────────┘          └─────────┘
  ```
  h1 runs tests/scripts/bgp_attr_inject_send.py. At session-up it
  announces 10.48.1.0/24 with AS_PATH "65061". On the trigger file
  /tmp/bgp_inbound_loop_withdraw.go it sends, in one write, 10.48.1.0/24
  again with AS_PATH "65061 65060 65063" — z1's own AS in the path, as
  when h1 has lost its route and now reaches the prefix through z1 — and
  the control prefix 10.48.2.0/24 with "65061".

  Config files:
  - z1.yaml: DUT — eBGP to h1 (passive) and to z2.
  - z2.yaml: z1's downstream eBGP peer.

  Scenario: Setup topology and establish sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.48.1/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.48.2/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.48.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.48.3" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_attr_inject_send.py 192.168.48.1 65061 192.168.48.2 4 192.168.48.2 /tmp/bgp_inbound_loop_withdraw 10.48.1.0/24 -- 10.48.1.0/24@65061,65060,65063 10.48.2.0/24" in namespace "h1"
    Then BGP session in "z1" to "192.168.48.2" should eventually be "Established"

  Scenario: The neighbor's path reaches z1 and z2
    Given the test topology exists
    Then show command "show bgp" in namespace "z1" should eventually contain "10.48.1.0/24"
    And BGP route in "z1" has "10.48.1.0/24" with "as_path" value "65061"
    And show command "show bgp" in namespace "z2" should eventually contain "10.48.1.0/24"

  Scenario: The looped replacement withdraws the earlier path at z1 and downstream
    Given the test topology exists
    When I execute "touch /tmp/bgp_inbound_loop_withdraw.go" in namespace "h1"
    # The control prefix came in the same write, after the looped UPDATE:
    # once it is in, the looped UPDATE has been processed.
    Then show command "show bgp" in namespace "z1" should eventually contain "10.48.2.0/24"
    # Pre-fix z1 dropped the looped UPDATE and kept the "65061" path h1
    # had just replaced.
    And show command "show bgp" in namespace "z1" should not contain "10.48.1.0/24"
    And BGP session in "z1" to "192.168.48.2" should be "Established"
    # z2 must lose it too: pre-fix z1 never withdrew it downstream.
    And show command "show bgp" in namespace "z2" should eventually contain "10.48.2.0/24"
    And show command "show bgp" in namespace "z2" should eventually not contain "10.48.1.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I execute "rm -f /tmp/bgp_inbound_loop_withdraw.go" in namespace "h1"
    And I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "h1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
