@serial
@ospfv2_passive
Feature: OSPFv2 passive interfaces advertise their prefix without forming adjacencies
  As a network operator
  I want `area <id> interface <n> passive true` to keep advertising
  the interface's prefix into the area while sending and accepting no
  Hellos — so stub networks are reachable without exposing an
  adjacency on them.

  Test Topology:
  ```
    a (10.0.0.1) -- 10.0.12.0/30 -- b (10.0.0.2) -- 10.0.23.0/30 -- c (10.0.0.3)
                     active link       ethc PASSIVE on b   c runs OSPF actively

    on router X the interface toward router Y is named "ethY".
  ```

  b's ethc is passive. Its /30 must appear in a's routing table (the
  stub prefix rides b's Router-LSA), while c — actively speaking OSPF
  on that segment — must never become b's neighbor.

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
    # Long enough that a c-b adjacency would certainly have formed if
    # the passive gate leaked a single Hello in either direction.
    And I wait 40 seconds

    # The active link works normally.
    Then show command "show ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ospf neighbor" in namespace "a" should contain "10.0.0.2"
    # The passive interface's prefix is advertised as a stub network.
    And show command "show ospf route" in namespace "a" should contain "10.0.23.0/30"
    And ping from "a" to "10.0.23.1" should succeed
    # No adjacency across the passive link, in either direction.
    And show command "show ospf neighbor" in namespace "b" should not contain "10.0.0.3"
    And show command "show ospf neighbor" in namespace "c" should not contain "10.0.0.2"
    # The passive interface reports its state.
    And show command "show ospf interface" in namespace "b" should contain "No Hellos (Passive interface)"

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "c"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "c"
    Then the test environment should be clean
