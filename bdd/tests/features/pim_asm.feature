@serial
@pim_asm
Feature: PIM ASM with a static RP — register, shared tree and SPT
  As a network operator
  I want an any-source IGMP join at the last-hop router to build a
  shared tree to the static RP, a new source's first-hop router to
  register it with the RP, the RP to join the source tree and stop
  the registers, and traffic to flow natively source→RP→receiver —
  the complete PIM-SM ASM control loop over three routers.

  r2 is the RP (10.1.22.2, its own interface address, configured
  statically on all three routers). h2 issues an any-source join for
  239.2.2.2 (IGMPv3 EXCLUDE{}); r3 (LHR) builds (*,G) toward the RP.
  h1 then sends: r1 (FHR/DR for the source subnet) registers with the
  RP, the RP joins (S,G) back toward r1 and answers Register-Stop —
  r1's register state must settle in suppression (RegPrune) — and
  h1's datagrams must arrive at h2 through the kernel MFCs of all
  three routers.

  Test Topology:
  ```
    h1 (10.1.21.2, sender) -- eth0/eth1 -- r1 -- eth2/eth3 -- r2(RP) -- eth4/eth5 -- r3 -- eth6/eth7 -- h2 (10.1.24.2, receiver)
                                 10.1.21.1    10.1.22.1/.2       10.1.23.1/.2          10.1.24.1
  ```

  Scenario: Register, shared tree and SPT converge and traffic flows
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
    And I add address "10.1.21.2/24" to interface "eth0" in namespace "h1"
    And I add address "10.1.24.2/24" to interface "eth7" in namespace "h2"

    # Control plane up: neighbors on both transit links, RP mapping known.
    Then show command "show pim neighbor" in namespace "r1" should eventually contain "10.1.22.2"
    And show command "show pim neighbor" in namespace "r3" should eventually contain "10.1.23.1"
    And show command "show pim rp-info" in namespace "r2" should contain "yes"

    # h2's any-source join builds the shared tree: (*,G) at the LHR,
    # joined toward the RP; the RP holds the (*,G) downstream state.
    When I spawn "timeout 150 python3 tests/scripts/asm_recv.py 239.2.2.2 10.1.24.2 5001 /tmp/pim_asm_rx" in namespace "h2"
    Then show command "show igmp groups" in namespace "r3" should eventually contain "239.2.2.2"
    And show command "show pim upstream" in namespace "r3" should eventually contain "(*, 239.2.2.2)"
    And show command "show pim upstream" in namespace "r3" should eventually contain "Joined"
    And show command "show mroute" in namespace "r2" should eventually contain "(*, 239.2.2.2)"

    # h1 starts sending: r1 registers, the RP builds (S,G) back toward
    # r1 and stops the registers; r1 settles in suppression.
    When I spawn "timeout 120 python3 tests/scripts/mcast_send.py 239.2.2.2 5001 10.1.21.2 90" in namespace "h1"
    Then show command "show mroute" in namespace "r2" should eventually contain "(10.1.21.2, 239.2.2.2)"
    And show command "show pim upstream" in namespace "r2" should eventually contain "(10.1.21.2, 239.2.2.2)"
    And show command "show pim upstream" in namespace "r1" should eventually contain "RegPrune"

    # Kernel MFCs along the native path.
    And command "ip mroute show" in namespace "r1" should eventually contain "Iif: eth1"
    And command "ip mroute show" in namespace "r2" should eventually contain "Iif: eth3"
    And command "ip mroute show" in namespace "r2" should eventually contain "eth4"
    And command "ip mroute show" in namespace "r3" should eventually contain "Iif: eth5"

    # The datapath proof: h1's datagrams arrive at h2 through all
    # three routers.
    And command "cat /tmp/pim_asm_rx" in namespace "h2" should eventually contain "ssm-hello"

  Scenario: Teardown topology
    When I execute "rm -f /tmp/pim_asm_rx" in namespace "h2"
    And I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    And I delete namespace "h1"
    And I delete namespace "h2"
    Then the test environment should be clean
