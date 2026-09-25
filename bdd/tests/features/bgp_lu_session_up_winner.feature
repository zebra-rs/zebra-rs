@serial
@bgp_lu_session_up_winner
Feature: A labeled-unicast neighbor that comes up late is dumped the best path (IPv4)
  As a network operator
  I want a labeled-unicast neighbor that establishes after my routes are
  in to receive each prefix's best path and label
  So a late session does not start out forwarding on a worse path until
  the next change for the prefix happens to correct it.

  Labeled-unicast is not update-group batched: a neighbor that comes up
  gets the Loc-RIB through a session-up dump. For a plain (non-AddPath)
  neighbor the dump took the LAST row of the prefix's candidate list —
  the path added or refreshed most recently — rather than the selected
  best path. The unicast and VPN dumps read the selected path.

  Test Topology:
  ```
  ┌──────────────────────────────────────────────────────────────┐
  │                     br0 192.168.52.0/24                      │
  └──────┬───────────────┬───────────────┬───────────────┬───────┘
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │   z2    │     │   z3    │     │   z1    │     │   z4    │
    │ AS65002 │     │ AS65002 │     │  (DUT)  │     │ AS65100 │
    │  .2     │     │  .3     │     │ AS65100 │     │  .4     │
    │lo1 10.52│     │lo1 10.52│     │  .1     │     │ (late)  │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
  ```
  z2 and z3 both originate 10.52.0.1/32 into IPv4 labeled-unicast. The
  two paths tie down to the BGP Identifier, so z2's (192.168.52.2) is
  z1's best. z3's path arrives second and is the newest candidate. z4, a
  plain iBGP labeled-unicast neighbor, starts only after that; z1 relays
  the prefix to it with the next-hop unchanged, so z4's next-hop names
  the path it was sent.

  Config files:
  - z1.yaml: DUT — label-v4 eBGP to z2 and z3, iBGP to z4.
  - z2.yaml, z3.yaml: originate 10.52.0.1/32.
  - z4.yaml: the late iBGP neighbor.

  Scenario: Setup topology; z1 learns z2's path, then z3's
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.52.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.52.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.52.3/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.52.4/24" on bridge "br0"
    And I create dummy interface "lo1" with address "10.52.0.1/32" in namespace "z2"
    And I create dummy interface "lo1" with address "10.52.0.1/32" in namespace "z3"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "192.168.52.2" should eventually be "Established"
    And show command "show bgp labeled-unicast" in namespace "z1" should eventually contain "10.52.0.1/32"
    When I apply config "z3.yaml" to namespace "z3"
    Then BGP session in "z1" to "192.168.52.3" should eventually be "Established"
    And show command "show bgp labeled-unicast" in namespace "z1" should eventually contain "192.168.52.3"

  Scenario: The late neighbor is dumped the best path, not the newest candidate
    Given the test topology exists
    When I start zebra-rs in namespace "z4"
    And I apply config "z4.yaml" to namespace "z4"
    Then BGP session in "z1" to "192.168.52.4" should eventually be "Established"
    And show command "show bgp labeled-unicast" in namespace "z4" should eventually contain "10.52.0.1/32"
    # Pre-fix z4 was dumped z3's path (next-hop 192.168.52.3), the newest
    # candidate, and kept it: nothing changed for the prefix afterwards.
    And show command "show bgp labeled-unicast" in namespace "z4" should contain "192.168.52.2"
    And show command "show bgp labeled-unicast" in namespace "z4" should not contain "192.168.52.3"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "z4"
    And I delete bridge "br0"
    Then the test environment should be clean
