@serial
@bgp_enforce_first_as
Feature: BGP enforce-first-as drops inbound updates whose AS_PATH does not start with the peer AS
  As a network operator
  I want `neighbor X enforce-first-as`
  So a peer that forwards routes without prepending its own AS first is not trusted.

  Test Topology (a point-to-point eBGP session):
  ```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │
   │ AS65001 │                  │ AS65002 │
   │  .0.1   │                  │  .0.2   │
   └─────────┘                  └─────────┘
   originates 10.0.0.1/32
  ```

  z1 originates 10.0.0.1/32. It also runs an outbound route-map toward z2
  that prepends a *foreign* AS (65099). zebra-rs applies the mandatory
  eBGP local-AS prepend first ("65001"), then the route-map prepend lands
  65099 left-most, so z2 receives AS_PATH "65099 65001". The left-most AS
  is 65099, not z1's own AS 65001.

  Normally z2 accepts that route (AS 65002 is not in the path, so there is
  no loop). With `enforce-first-as` on z2's session toward z1, z2 instead
  requires the left-most AS to be the peer's own AS (65001) and discards
  the update because it starts with 65099.

  Config files:
  - z1.yaml:          z1 originates 10.0.0.1/32, prepends foreign AS 65099 on egress
  - z2-base.yaml:     z2 without enforce-first-as (accepts the route)
  - z2-enforce.yaml:  z2 with `enforce-first-as` toward 192.168.0.1

  Scenario: Setup the topology and establish the session
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2-base.yaml" to namespace "z2"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: Without enforce-first-as z2 accepts the foreign-first-AS route
    Given the test topology exists
    # z2 receives 10.0.0.1/32 with AS_PATH "65099 65001". The left-most AS
    # is 65099 (not z1's 65001), but the strict check is off, so z2 keeps it.
    Then BGP route in "z2" has "10.0.0.1/32"

  Scenario: With enforce-first-as z2 drops the route
    Given the test topology exists
    When I apply config "z2-enforce.yaml" to namespace "z2"
    # Bounce the session so z2 re-receives 10.0.0.1/32 and re-runs the
    # inbound first-AS check, which now drops it (first AS 65099 != 65001).
    And I run "clear bgp ipv4 neighbor 192.168.0.1" in namespace "z2"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP route in "z2" does not have "10.0.0.1/32"
    And show command "show ip bgp neighbors" in namespace "z2" should contain "Enforce-first-AS"

  # Pure P2P topology (no bridge): deleting each namespace destroys the veth
  # pair ends it holds, so only the daemons and namespaces need teardown.
  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
