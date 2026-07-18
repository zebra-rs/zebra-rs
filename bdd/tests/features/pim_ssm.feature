@serial
@pim_ssm
Feature: PIM SSM (S,G) forwarding end to end across two routers
  As a network operator
  I want an IGMPv3 source-specific join at the last-hop router to
  build an (S,G) shortest-path tree back to the first-hop router and
  program the kernel multicast forwarding cache on both, so real
  traffic from the source reaches the receiver — the first complete
  PIM-SM/SSM control-plane-to-dataplane slice.

  h1 sends UDP to the SSM group 232.1.1.1. h2 issues a source-specific
  join for (10.1.14.2, 232.1.1.1). r2 (LHR) must translate the IGMPv3
  membership into a PIM (S,G) Join toward r1 (RPF via a static route),
  r1 (FHR, source directly connected) must accept the Join into its
  downstream state, and both must install kernel MFC entries that
  forward h1's datagrams to h2.

  Test Topology:
  ```
    h1 (10.1.14.2, sender) --- eth4/eth3 --- r1 --- eth1/eth2 --- r2 --- eth5/eth6 --- h2 (10.1.15.2, receiver)
                                   10.1.14.1     10.1.13.1/.2       10.1.15.1
  ```

  Scenario: SSM join builds the (S,G) tree and traffic flows
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "h1"
    And I create namespace "h2"
    And I connect namespace "r1" interface "eth1" to namespace "r2" interface "eth2"
    And I connect namespace "r1" interface "eth3" to namespace "h1" interface "eth4"
    And I connect namespace "r2" interface "eth5" to namespace "h2" interface "eth6"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I add address "10.1.14.2/24" to interface "eth4" in namespace "h1"
    And I add address "10.1.15.2/24" to interface "eth6" in namespace "h2"

    # PIM neighborship on the transit link first.
    Then show command "show pim neighbor" in namespace "r2" should eventually contain "10.1.13.1"

    # h2 source-specifically joins (10.1.14.2, 232.1.1.1): r2 turns the
    # IGMPv3 membership into an (S,G) Join toward r1.
    When I spawn "timeout 150 python3 tests/scripts/ssm_recv.py 232.1.1.1 10.1.14.2 10.1.15.2 5001 /tmp/pim_ssm_rx" in namespace "h2"
    Then show command "show igmp groups" in namespace "r2" should eventually contain "232.1.1.1"
    And show command "show pim upstream" in namespace "r2" should eventually contain "Joined"
    And show command "show mroute" in namespace "r2" should eventually contain "232.1.1.1"
    # r1 learned the (S,G) from r2's PIM Join — no IGMP on that path.
    And show command "show mroute" in namespace "r1" should eventually contain "232.1.1.1"

    # Kernel MFC on both routers, with the expected IIF/OIF split.
    And command "ip mroute show" in namespace "r1" should eventually contain "Iif: eth3"
    And command "ip mroute show" in namespace "r1" should eventually contain "eth1"
    And command "ip mroute show" in namespace "r2" should eventually contain "Iif: eth2"
    And command "ip mroute show" in namespace "r2" should eventually contain "eth5"

    # The datapath proof: h1's datagrams arrive at h2's receiver.
    When I spawn "timeout 120 python3 tests/scripts/mcast_send.py 232.1.1.1 5001 10.1.14.2 90" in namespace "h1"
    Then command "cat /tmp/pim_ssm_rx" in namespace "h2" should eventually contain "ssm-hello"

  Scenario: Teardown topology
    When I execute "rm -f /tmp/pim_ssm_rx" in namespace "h2"
    And I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "h1"
    And I delete namespace "h2"
    Then the test environment should be clean
