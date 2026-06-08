@serial
@bgp_disable_connected_check
Feature: BGP disable-connected-check (eBGP connected-network check)
  As a network operator
  I want a single-hop eBGP session over loopback addresses to be held down
  by default (the neighbor is not on a directly-connected subnet) and to
  come up once `disable-connected-check` is set, confirming both the check
  and its override end-to-end.

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │ 10.0.0. │     │ 10.0.0. │
           │  1/24   │     │  2/24   │
           │ lo .255 │     │ lo .255 │
           │  .0.1/32│     │  .0.2/32│
           └─────────┘     └─────────┘
  ```

  z1 and z2 are directly connected at layer 2 over br0 (10.0.0.0/24), but
  peer eBGP using their loopbacks (10.255.0.1 ↔ 10.255.0.2), each reachable
  only via a static route — so neither peering address is on a connected
  subnet. A TTL-1 packet still reaches the L2-adjacent peer, so the only
  thing standing between the two routers is the connected check.

  Config files:
  - z{1,2}-base.yaml: loopback peering, no disable-connected-check.
  - z{1,2}-disable.yaml: same, plus `disable-connected-check`.

  Scenario: The connected check holds a loopback eBGP session down
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "10.0.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "10.0.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2-base.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "10.255.0.2" should not be "Established"
    And BGP session in "z2" to "10.255.0.1" should not be "Established"
    And BGP route in "z2" does not have "10.1.1.1/32"

  Scenario: disable-connected-check brings the loopback eBGP session up
    Given the test topology exists
    When I apply config "z1-disable.yaml" to namespace "z1"
    And I apply config "z2-disable.yaml" to namespace "z2"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z1" to "10.255.0.2" should be "Established"
    And BGP session in "z2" to "10.255.0.1" should be "Established"
    And BGP route in "z2" has "10.1.1.1/32"
    And BGP route in "z1" has "10.2.2.2/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
