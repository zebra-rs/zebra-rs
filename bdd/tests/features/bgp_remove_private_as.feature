@serial
@bgp_remove_private_as
Feature: BGP remove-private-as strips private ASNs from the egress AS_PATH
  As a network operator
  I want `neighbor X remove-private-as`
  So a downstream eBGP peer never learns the private internal AS numbers
  of my network.

  Test Topology (a line; z1 uses a private AS behind public z2):
  ```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │ i2────────────i1 │   z3    │
   │ AS65001 │                  │ AS 100  │                  │ AS 200  │
   │ .0.1    │                  │.0.2 .1.2│                  │ .1.3    │
   └─────────┘                  └─────────┘                  └─────────┘
   private AS                    public AS                    public AS
  ```

  z1 originates 10.0.0.1/32; z2 learns it with AS_PATH "65001". When z2
  re-advertises it to z3 it normally prepends its own AS, sending
  "100 65001" — leaking z1's private AS 65001 to z3. With
  `remove-private-as` on z2's session toward z3, z2 strips the private
  65001 before prepending, so z3 receives just "100". The neighbor's own
  AS (z3's 200) would always be kept for loop prevention, but here it is
  not in the path.

  Config files:
  - z1.yaml:          z1 (private AS 65001) originates 10.0.0.1/32
  - z3.yaml:          z3 plain
  - z2-base.yaml:     z2 without remove-private-as
  - z2-remove.yaml:   z2 with `remove-private-as` toward 192.168.1.3

  Scenario: Setup line topology and establish all sessions
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I create namespace "z3"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I connect namespace "z2" interface "i2" to namespace "z3" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2-base.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z2" to "192.168.1.3" should be "Established"
    And BGP session in "z3" to "192.168.1.2" should be "Established"

  Scenario: Without remove-private-as the private AS leaks to z3
    Given the test topology exists
    # z3 learns the route, but the AS_PATH still carries z1's private AS.
    Then BGP route in "z3" has "10.0.0.1/32"
    And BGP route in "z3" has "10.0.0.1/32" with "as_path" value "100 65001"

  Scenario: remove-private-as strips the private AS on egress to z3
    Given the test topology exists
    When I apply config "z2-remove.yaml" to namespace "z2"
    # Bounce the z2<->z3 session so z2 re-advertises 10.0.0.1/32 with the
    # stripped AS_PATH "100".
    And I run "clear bgp ipv4 neighbor 192.168.1.3" in namespace "z2"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z3" to "192.168.1.2" should be "Established"
    And BGP route in "z3" has "10.0.0.1/32"
    And BGP route in "z3" has "10.0.0.1/32" with "as_path" value "100"
    And show command "show ip bgp neighbors" in namespace "z2" should contain "Private AS removal"
