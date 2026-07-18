@serial
@bgp_graceful_restart
Feature: Graceful Restart advertises a usable Restart Time
  As a network operator
  I want a graceful-restart-enabled neighbor to advertise a sane RFC
  4724 Restart Time, so a helper retains routes across a real restart.

  Test Topology:
  ```
  z1 (AS65001) ──eBGP── z2 (AS65002)
  192.168.0.1/24        192.168.0.2/24
  ```
  Both enable `afi-safi ipv4 graceful-restart`. Review finding #15: the
  enable marker stored `1`, advertised verbatim as the Restart Time, so
  a helper flushed retained routes after ~1s — no forwarding continuity.
  The default is now 120s.

  Scenario: Setup and establish the session
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: The advertised/received Restart Time is the sane default, not 1
    Given the test topology exists
    Then show command "show bgp neighbor 192.168.0.1" in namespace "z2" should contain "restart time:120"
    And show command "show bgp neighbor 192.168.0.1" in namespace "z2" should not contain "restart time:1)"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "restart time:120"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
