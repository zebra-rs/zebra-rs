@serial
@pim6_bsr
Feature: PIMv6 Bootstrap Router election and RP-set distribution
  As a network operator
  I want a candidate BSR to win the election, collect candidate-RP
  advertisements, and flood the RP-set in Bootstrap messages so every
  PIMv6 router learns the group-to-RP mapping without static config —
  then run the ASM control loop on the BSR-learned RP.

  r2 is candidate-BSR and candidate-RP (2001:db8:22::2). r1 and r3 must
  learn both the elected BSR and the RP purely from flooded BSMs. The
  Bootstrap messages are link-local-sourced multicast (like Hellos); the
  BSR / RP addresses they carry are the configured globals, so the
  election and RP mapping are deterministic.

  Test Topology:
  ```
    h1 (2001:db8:21::10, sender) -- eth0/eth1 -- r1 -- eth2/eth3 -- r2(C-BSR,C-RP) -- eth4/eth5 -- r3 -- eth6/eth7 -- h2 (2001:db8:24::10, receiver)
                                       2001:db8:21::1   2001:db8:22::1/.2         2001:db8:23::1/.2         2001:db8:24::1
  ```

  Scenario: BSR election, RP-set distribution and ASM traffic
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I create namespace "h1"
    And I create namespace "h2"
    And I connect namespace "h1" interface "eth0" to namespace "r1" interface "eth1"
    And I connect namespace "r1" interface "eth2" to namespace "r2" interface "eth3"
    And I connect namespace "r2" interface "eth4" to namespace "r3" interface "eth5"
    And I connect namespace "r3" interface "eth6" to namespace "h2" interface "eth7"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    And I add address "2001:db8:21::10/64" to interface "eth0" in namespace "h1"
    And I add address "2001:db8:24::10/64" to interface "eth7" in namespace "h2"

    # r2 claims the BSR role; r1 and r3 learn it from flooded BSMs.
    Then show command "show pim ipv6 bsr" in namespace "r2" should eventually contain "Elected"
    And show command "show pim ipv6 bsr" in namespace "r1" should eventually contain "2001:db8:22::2"
    And show command "show pim ipv6 bsr" in namespace "r3" should eventually contain "2001:db8:22::2"

    # The RP mapping arrives via the BSM RP-set — no static config.
    And show command "show pim ipv6 rp-info" in namespace "r1" should eventually contain "bsr"
    And show command "show pim ipv6 rp-info" in namespace "r3" should eventually contain "2001:db8:22::2"

    # The ASM control loop runs on the learned RP: shared tree from h2's
    # join, register cycle from h1's traffic, payload delivered.
    When I spawn "timeout 160 python3 tests/scripts/asm_recv6.py ff0e::9 eth7 5001 /tmp/pim6_bsr_rx" in namespace "h2"
    Then show command "show pim ipv6 upstream" in namespace "r3" should eventually contain "(*, ff0e::9)"
    And show command "show pim ipv6 mroute" in namespace "r2" should eventually contain "(*, ff0e::9)"
    When I spawn "timeout 130 python3 tests/scripts/mcast_send6.py ff0e::9 5001 eth0 100" in namespace "h1"
    Then show command "show pim ipv6 mroute" in namespace "r2" should eventually contain "2001:db8:21::10"
    And show command "show pim ipv6 upstream" in namespace "r1" should eventually contain "RegPrune"
    And command "cat /tmp/pim6_bsr_rx" in namespace "h2" should eventually contain "ssm-hello"

  Scenario: Teardown topology
    When I execute "rm -f /tmp/pim6_bsr_rx" in namespace "h2"
    And I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    And I delete namespace "h1"
    And I delete namespace "h2"
    Then the test environment should be clean
