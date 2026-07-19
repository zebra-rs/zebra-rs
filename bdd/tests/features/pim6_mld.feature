@serial
@pim6_mld
Feature: MLD membership tracking on a PIMv6 router
  As a network operator
  I want a zebra-rs router running MLD on an IPv6 interface to act as
  the querier and learn group memberships from MLDv2 reports, so the
  MLD codec (RFC 3810 over ICMPv6) driving the shared Gm<Ipv6> engine
  is exercised host-to-router.

  A host joins an IPv6 multicast group; its kernel emits an MLDv2
  report to ff02::16, which the router's querier (joined to ff02::16)
  receives and records as membership.

  Test Topology:
  ```
    r1 (2001:db8:1::1/64, MLD querier) --- veth --- h1 (2001:db8:1::9/64)
       eth1                                            eth2
  ```

  Scenario: An MLDv2 report creates group membership on the querier
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "h1"
    And I connect namespace "r1" interface "eth1" to namespace "h1" interface "eth2"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    And I add address "2001:db8:1::9/64" to interface "eth2" in namespace "h1"

    # h1 joins an IPv6 group; the kernel's MLDv2 report — plus responses
    # to r1's periodic MLD queries — teach r1 the membership.
    When I spawn "timeout 90 python3 tests/scripts/mld_join.py ff3e::1 eth2 85" in namespace "h1"
    Then show command "show pim ipv6 mld groups" in namespace "r1" should eventually contain "ff3e::1"

  Scenario: Teardown topology
    When I stop zebra-rs in namespace "r1"
    And I delete namespace "r1"
    And I delete namespace "h1"
    Then the test environment should be clean
