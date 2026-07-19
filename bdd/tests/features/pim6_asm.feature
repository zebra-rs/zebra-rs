@serial
@pim6_asm
Feature: PIMv6 ASM with a static RP — register, shared tree and SPT
  As a network operator
  I want an any-source MLD join at the last-hop router to build a shared
  tree to the static RP, a new IPv6 source's first-hop router to register
  it with the RP, the RP to join the source tree and stop the registers,
  and traffic to flow natively source→RP→receiver — the complete PIMv6-SM
  ASM control loop over three routers.

  r2 is the RP (2001:db8:12::2, its own interface address, configured
  statically on all three routers). h2 issues an any-source join for
  ff0e::1 (MLDv2 EXCLUDE{}); r3 (LHR) builds (*,G) toward the RP. h1 then
  sends: r1 (FHR/DR for the source subnet) registers with the RP, the RP
  joins (S,G) back toward r1 and answers Register-Stop — r1's register
  state must settle in RegPrune — and h1's datagrams must arrive at h2
  through the kernel MRT6 MFCs of all three routers.

  Test Topology:
  ```
    h1 (2001:db8:1::9, sender) -- eth0/eth1 -- r1 -- eth2/eth3 -- r2(RP) -- eth4/eth5 -- r3 -- eth6/eth7 -- h2 (2001:db8:24::9, receiver)
                                    2001:db8:1::1   2001:db8:12::1/.2       2001:db8:23::1/.2         2001:db8:24::1
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
    And I add address "2001:db8:1::9/64" to interface "eth0" in namespace "h1"
    And I add address "2001:db8:24::9/64" to interface "eth7" in namespace "h2"

    # Control plane up: neighbors on both transit links.
    Then show command "show pim ipv6 neighbor" in namespace "r1" should eventually contain "fe80"
    And show command "show pim ipv6 neighbor" in namespace "r3" should eventually contain "fe80"

    # h2's any-source join builds the shared tree: (*,G) at the LHR,
    # joined toward the RP; the RP holds the (*,G) downstream state.
    When I spawn "timeout 180 python3 tests/scripts/asm_recv6.py ff0e::1 eth7 5001 /tmp/pim6_asm_rx" in namespace "h2"
    Then show command "show pim ipv6 mld groups" in namespace "r3" should eventually contain "ff0e::1"
    And show command "show pim ipv6 upstream" in namespace "r3" should eventually contain "(*, ff0e::1)"
    And show command "show pim ipv6 upstream" in namespace "r3" should eventually contain "Joined"
    And show command "show pim ipv6 mroute" in namespace "r2" should eventually contain "(*, ff0e::1)"

    # h1 starts sending: r1 registers, the RP builds (S,G) back toward r1
    # and stops the registers; r1 settles in suppression.
    When I spawn "timeout 150 python3 tests/scripts/mcast_send6.py ff0e::1 5001 eth0 120" in namespace "h1"
    Then show command "show pim ipv6 mroute" in namespace "r2" should eventually contain "2001:db8:1::9"
    And show command "show pim ipv6 upstream" in namespace "r2" should eventually contain "2001:db8:1::9"
    And show command "show pim ipv6 upstream" in namespace "r1" should eventually contain "RegPrune"

    # Kernel MRT6 MFCs along the native path.
    And command "ip -6 mroute show" in namespace "r1" should eventually contain "Iif: eth1"
    And command "ip -6 mroute show" in namespace "r2" should eventually contain "Iif: eth3"
    And command "ip -6 mroute show" in namespace "r2" should eventually contain "eth4"
    And command "ip -6 mroute show" in namespace "r3" should eventually contain "Iif: eth5"

    # The datapath proof: h1's datagrams arrive at h2 through all three routers.
    And command "cat /tmp/pim6_asm_rx" in namespace "h2" should eventually contain "ssm-hello"

  Scenario: Teardown topology
    When I execute "rm -f /tmp/pim6_asm_rx" in namespace "h2"
    And I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    And I delete namespace "h1"
    And I delete namespace "h2"
    Then the test environment should be clean
