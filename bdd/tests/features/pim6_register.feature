@serial
@pim6_register
Feature: PIMv6 FHR Register to a static RP over unicast IPv6
  As a network operator
  I want a first-hop router to encapsulate a new IPv6 source's traffic
  in a PIM Register and unicast it to the statically configured RP, and
  the RP to answer Register-Stop so the FHR settles in suppression — the
  PIMv6 unicast Register control loop (transport slice of ASM), before
  the full shared-tree datapath.

  Unlike link-local PIM control (Hello / J/P / Assert to ff02::d), the
  Register and Register-Stop are unicast between the FHR and the RP: the
  FHR sources them from a routable (non-link-local) address so the RP can
  reply, and the RP accepts a non-link-local source on a unicast
  destination. There is no receiver, so the RP has no shared tree and
  answers Register-Stop immediately; the FHR's register state settles in
  RegPrune.

  Test Topology:
  ```
    h1 (2001:db8:1::9, source) --- eth0/eth1 --- r1 (FHR) --- eth2/eth3 --- r2 (RP, 2001:db8:12::2)
                                       2001:db8:1::1        2001:db8:12::1/.2
  ```

  Scenario: FHR registers and the RP stops it
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "h1"
    And I connect namespace "h1" interface "eth0" to namespace "r1" interface "eth1"
    And I connect namespace "r1" interface "eth2" to namespace "r2" interface "eth3"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I add address "2001:db8:1::9/64" to interface "eth0" in namespace "h1"

    # PIMv6 neighborship on the transit link, and the RP knows it is the RP.
    Then show command "show pim ipv6 neighbor" in namespace "r1" should eventually contain "fe80"
    And show command "show pim ipv6 neighbor" in namespace "r2" should eventually contain "fe80"

    # h1 sends to the ASM group ff0e::1: r1 (FHR/DR) encapsulates the
    # source in a unicast PIM Register to the RP.
    When I spawn "timeout 120 python3 tests/scripts/mcast_send6.py ff0e::1 5001 eth0 90" in namespace "h1"

    # The RP received the Register and created the (S,G) for the source.
    Then show command "show pim ipv6 upstream" in namespace "r2" should eventually contain "ff0e::1"
    And show command "show pim ipv6 upstream" in namespace "r2" should eventually contain "2001:db8:1::9"

    # The RP answered Register-Stop (no receiver); r1 settles in
    # suppression — the proof that the unicast Register round-trip closed.
    And show command "show pim ipv6 upstream" in namespace "r1" should eventually contain "RegPrune"

  Scenario: Teardown topology
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "h1"
    Then the test environment should be clean
