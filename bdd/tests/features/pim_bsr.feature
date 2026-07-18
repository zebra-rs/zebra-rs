@serial
@pim_bsr
Feature: PIM Bootstrap Router elects itself and distributes the RP-set
  As a network operator
  I want a candidate BSR to win the election, collect candidate-RP
  advertisements and flood the group-to-RP mapping in Bootstrap
  Messages, so every router in the domain learns the RP without any
  static configuration — and the full ASM control loop (shared tree,
  register, SPT) runs on the learned mapping.

  Same chain as the pim_asm feature, but NO router has a static RP:
  r2 is candidate-BSR and candidate-RP (10.9.22.2). r1 and r3 must
  learn both the elected BSR and the RP purely from flooded BSMs,
  after which an any-source join at h2 and a sender at h1 must
  converge exactly as the static-RP scenario did.

  Test Topology:
  ```
    h1 (10.9.21.10, sender) -- eth0/eth1 -- r1 -- eth2/eth3 -- r2(C-BSR,C-RP) -- eth4/eth5 -- r3 -- eth6/eth7 -- h2 (10.9.24.10, receiver)
                                  10.9.21.1    10.9.22.1/.2          10.9.23.1/.2               10.9.24.1
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
    And I add address "10.9.21.10/24" to interface "eth0" in namespace "h1"
    And I add address "10.9.24.10/24" to interface "eth7" in namespace "h2"

    # r2 claims the BSR role; r1 and r3 learn it from flooded BSMs.
    Then show command "show pim bsr" in namespace "r2" should eventually contain "Elected"
    And show command "show pim bsr" in namespace "r1" should eventually contain "10.9.22.2"
    And show command "show pim bsr" in namespace "r3" should eventually contain "10.9.22.2"

    # The RP mapping arrives via the BSM RP-set — no static config.
    And show command "show pim rp-info" in namespace "r1" should eventually contain "bsr"
    And show command "show pim rp-info" in namespace "r3" should eventually contain "10.9.22.2"

    # The ASM control loop runs on the learned RP: shared tree from
    # h2's join, register cycle from h1's traffic, payload delivered.
    When I spawn "timeout 150 python3 tests/scripts/asm_recv.py 239.9.9.9 10.9.24.10 5001 /tmp/pim_bsr_rx" in namespace "h2"
    Then show command "show pim upstream" in namespace "r3" should eventually contain "(*, 239.9.9.9)"
    And show command "show mroute" in namespace "r2" should eventually contain "(*, 239.9.9.9)"
    When I spawn "timeout 120 python3 tests/scripts/mcast_send.py 239.9.9.9 5001 10.9.21.10 90" in namespace "h1"
    Then show command "show mroute" in namespace "r2" should eventually contain "(10.9.21.10, 239.9.9.9)"
    And show command "show pim upstream" in namespace "r1" should eventually contain "RegPrune"
    And command "cat /tmp/pim_bsr_rx" in namespace "h2" should eventually contain "ssm-hello"

  Scenario: Teardown topology
    When I execute "rm -f /tmp/pim_bsr_rx" in namespace "h2"
    And I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    And I delete namespace "h1"
    And I delete namespace "h2"
    Then the test environment should be clean
