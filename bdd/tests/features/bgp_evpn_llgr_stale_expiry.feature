@serial
@bgp_evpn_llgr_stale_expiry
Feature: LLGR stale EVPN rows expire after the stale time when the peer never returns
  As a network operator
  I want a peer's long-lived-graceful-restart stale routes to be swept
  when the stale time elapses, so a peer that goes down for good does
  not leave its routes selected, installed and advertised forever.

  Test Topology:
  ```
  z1 (AS 65001) ──iBGP (evpn)── z2
  192.168.0.1/24                 192.168.0.2/24
  ```
  Both ends enable `long-lived-graceful-restart` for the family with a
  10-second stale time. z1 originates one route. When z1's daemon is
  stopped, z2 retains the route stale (RFC 9494) — and must sweep it
  once the 10 seconds are up. Review finding #9: the only stale sweeper
  walked the VPNv4 table, so stale EVPN rows never expired.

  Scenario: Setup topology and establish the session
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: z2 holds z1's route
    Given the test topology exists
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "10.1.0.0"

  Scenario: z1 dies for good and its stale route is swept after the stale time
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I wait 3 seconds for BGP to operate
    # Retained stale first (LLGR), ...
    Then show command "show bgp evpn" in namespace "z2" should contain "10.1.0.0"
    # ... and gone once the 10-second stale time has elapsed. Pre-fix the
    # row stayed for the daemon's life.
    And show command "show bgp evpn" in namespace "z2" should eventually not contain "10.1.0.0"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
