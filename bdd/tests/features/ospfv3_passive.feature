@serial
@ospfv3_passive
Feature: OSPFv3 passive interfaces advertise their prefix without forming adjacencies
  As a network operator
  I want `area <id> interface <n> passive true` on OSPFv3 to keep
  advertising the interface's prefix (Intra-Area-Prefix-LSA) while
  sending and accepting no Hellos — mirroring ospfv2_passive.

  Test Topology (v6 mirror of ospfv2_passive):
  ```
    a -- 2001:db8:12::/64 -- b -- 2001:db8:23::/64 -- c
          active link           ethc PASSIVE on b     c active
  ```

  Scenario: Passive interface prefix advertises; no adjacency forms across it
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I connect namespace "b" interface "ethc" to namespace "c" interface "ethb"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "c"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "c.yaml" to namespace "c"
    And I wait 40 seconds

    Then show command "show ospfv3 neighbor" in namespace "a" should contain "Full"
    And show command "show ospfv3 neighbor" in namespace "a" should contain "10.0.0.2"
    # The passive interface's /64 is advertised via Intra-Area-Prefix.
    And show command "show ospfv3 route" in namespace "a" should contain "2001:db8:23::/64"
    And ping from "a" to "2001:db8:23::1" should succeed
    # No adjacency across the passive link, in either direction.
    And show command "show ospfv3 neighbor" in namespace "b" should not contain "10.0.0.3"
    And show command "show ospfv3 neighbor" in namespace "c" should not contain "10.0.0.2"

  Scenario: Teardown topology
    # Separate scenario so cleanup still runs when a step above fails
    # (a failed step skips the rest of its own scenario only).
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "c"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "c"
    Then the test environment should be clean
