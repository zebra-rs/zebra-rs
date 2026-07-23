@serial
@bgp_vrf_neighbor_auth
Feature: Per-VRF BGP neighbor authentication (TCP-MD5 password, TCP-AO key-chain)
  As an operator of an L3VPN PE
  I want `router bgp vrf <name> neighbor <addr> {password | tcp-ao}` to
  authenticate the per-VRF CE session
  So that a matching key establishes and a wrong key is actually rejected
  — proving the per-VRF neighbor keys the connect socket AND the VRF's own
  listener, not that auth is silently ignored.

  One matching + one mismatching CE per knob:
   * CE1 — password matching PE1's secret            → Established
   * CE2 — password different from PE1's             → never Established
   * CE3 — tcp-ao key-chain matching PE1's           → Established
   * CE4 — tcp-ao key-chain with a wrong key-string  → never Established

  The matching cases exercise both auth directions (PE-initiated dial via
  the VRF-bound connect socket AND CE-initiated dial via the VRF listener);
  the mismatching cases are the regression guard that a bad key can't slip
  through.

  Test Topology (5 namespaces, all CE links in vrf-cust):
  ```
   ce1  ce2   ce3  ce4
     \   |     |   /
        pe1 (65000, vrf-cust)
  ```

  Scenario: Build the auth VRF topology
    Given a clean test environment
    When I create namespace "ce1"
    And I create namespace "pe1"
    And I create namespace "ce2"
    And I create namespace "ce3"
    And I create namespace "ce4"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I connect namespace "pe1" interface "ce2" to namespace "ce2" interface "pe1"
    And I connect namespace "pe1" interface "ce3" to namespace "ce3" interface "pe1"
    And I connect namespace "pe1" interface "ce4" to namespace "ce4" interface "pe1"
    And I start zebra-rs in namespace "ce1"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "ce2"
    And I start zebra-rs in namespace "ce3"
    And I start zebra-rs in namespace "ce4"
    And I apply config "ce1.yaml" to namespace "ce1"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "ce2.yaml" to namespace "ce2"
    And I apply config "ce3.yaml" to namespace "ce3"
    And I apply config "ce4.yaml" to namespace "ce4"
    And I wait 15 seconds for BGP to operate

  Scenario: A matching TCP-MD5 password establishes the CE session
    Given the test topology exists
    Then BGP session in "ce1" to "10.1.0.1" should eventually be "Established"

  Scenario: A mismatched TCP-MD5 password is rejected
    # By now the matching CE1 session is up, so the daemons have been
    # dialing for a while; a wrong-key session would already be up if the
    # password were ignored. It is not: the kernel MD5 check drops the
    # handshake, so CE2 never leaves Connect/Active.
    Given the test topology exists
    Then BGP session in "ce2" to "10.2.0.1" should not be "Established"

  Scenario: A matching TCP-AO key-chain establishes the CE session
    Given the test topology exists
    Then BGP session in "ce3" to "10.3.0.1" should eventually be "Established"

  Scenario: A mismatched TCP-AO key-string is rejected
    Given the test topology exists
    Then BGP session in "ce4" to "10.4.0.1" should not be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "ce2"
    And I stop zebra-rs in namespace "ce3"
    And I stop zebra-rs in namespace "ce4"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    And I delete namespace "ce2"
    And I delete namespace "ce3"
    And I delete namespace "ce4"
    Then the test environment should be clean
