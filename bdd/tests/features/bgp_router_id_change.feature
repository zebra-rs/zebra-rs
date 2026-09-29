@serial
@bgp_router_id_change
Feature: A BGP router-id change reaches the neighbors
  As a network operator
  I want a change of the BGP router-id — configured, or the RIB-derived
  `system router-id` — to reach every established neighbor
  So each neighbor knows us by the identifier our loop checks now use.

  A neighbor learns our BGP Identifier only from our OPEN. A router-id
  change used to leave every established session on the old identifier
  ("the next OPEN picks up the new one"), while our own checks moved to
  the new one: a route of ours a reflector sends back carries the old
  identifier as ORIGINATOR_ID and passed the inbound loop check. The
  session is now reset, as FRR, IOS and Junos do. The twin is
  `bgp_router_id_change_v6`, over an IPv6 session.

  Test Topology:
  ```
  ┌─────────────────────────────────────┐
  │        br0 10.0.31.0/24             │
  └───────┬─────────────────────┬───────┘
     ┌────┴────┐           ┌────┴────┐
     │   z1    │── iBGP ───│   z2    │
     │ AS65000 │           │ AS65000 │
     │ .1      │           │ .2      │
     └─────────┘           └─────────┘
  ```
  z1 takes its router-id from `system router-id` (192.168.31.1), then
  from a changed one (192.168.31.21), then from a configured
  `router bgp global router-id` (192.168.31.11), and back. z2 reads the
  identifier z1 sent in its OPEN off `show bgp neighbor`.

  Config files:
  - z1.yaml: `system router-id 192.168.31.1`; iBGP to z2, no BGP router-id.
  - z2.yaml: router-id 192.168.31.2; iBGP to z1.

  Scenario: Setup; z2 knows z1 by its system router-id
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "10.0.31.1/24" on bridge "br0"
    And I create namespace "z2" with IP "10.0.31.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then BGP session in "z1" to "10.0.31.2" should eventually be "Established"
    And show command "show bgp neighbor 10.0.31.1" in namespace "z2" should eventually contain "remote router ID 192.168.31.1,"

  Scenario: A changed system router-id reaches z2
    Given the test topology exists
    When I apply command "set system router-id 192.168.31.21" in namespace "z1"
    # z1 takes the new router-id at once; pre-fix its session stayed up
    # on the old identifier, so z2 kept knowing z1 as 192.168.31.1.
    Then show command "show bgp neighbor 10.0.31.2" in namespace "z1" should eventually contain "local router ID 192.168.31.21"
    And show command "show bgp neighbor 10.0.31.1" in namespace "z2" should eventually contain "remote router ID 192.168.31.21,"
    And BGP session in "z1" to "10.0.31.2" should eventually be "Established"
    And show command "show bgp neighbor 10.0.31.2" in namespace "z1" should contain "due to Router ID changed"

  Scenario: A configured BGP router-id reaches z2
    Given the test topology exists
    When I apply command "set router bgp global router-id 192.168.31.11" in namespace "z1"
    Then show command "show bgp neighbor 10.0.31.2" in namespace "z1" should eventually contain "local router ID 192.168.31.11"
    And show command "show bgp neighbor 10.0.31.1" in namespace "z2" should eventually contain "remote router ID 192.168.31.11,"
    And BGP session in "z1" to "10.0.31.2" should eventually be "Established"

  Scenario: Deleting the configured BGP router-id falls back to the system one
    Given the test topology exists
    When I apply command "delete router bgp global router-id" in namespace "z1"
    Then show command "show bgp neighbor 10.0.31.2" in namespace "z1" should eventually contain "local router ID 192.168.31.21"
    And show command "show bgp neighbor 10.0.31.1" in namespace "z2" should eventually contain "remote router ID 192.168.31.21,"
    And BGP session in "z1" to "10.0.31.2" should eventually be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
