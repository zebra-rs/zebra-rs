@serial
@pim_igmp
Feature: IGMP membership tracking and querier election
  As a network operator
  I want a zebra-rs router to learn IGMP group membership from
  attached hosts and to elect a single querier per LAN, so the
  receiver side of the multicast control plane works before PIM
  trees are built on top of it.

  r1 runs IGMP on two links: toward r2 (router-to-router, exercising
  querier election — the lower address 10.1.13.1 must win and r2 must
  step down to Non-Querier) and toward host h1, which joins group
  239.1.1.1 with a socat receiver (the kernel emits an IGMPv3 report);
  r1 must show the group in EXCLUDE mode.

  Test Topology:
  ```
    r2 (10.1.13.2) --- eth2/eth1 --- r1 (10.1.13.1)
                                     r1 (10.1.14.1) --- eth3/eth4 --- h1 (10.1.14.2, receiver)
  ```

  Scenario: Querier election and receiver join
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "h1"
    And I connect namespace "r1" interface "eth1" to namespace "r2" interface "eth2"
    And I connect namespace "r1" interface "eth3" to namespace "h1" interface "eth4"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I add address "10.1.14.2/24" to interface "eth4" in namespace "h1"

    # Querier election on the r1-r2 link: the lower address wins.
    Then show command "show igmp interface" in namespace "r1" should eventually contain "Querier"
    And show command "show igmp interface" in namespace "r1" should not contain "Non-Querier"
    And show command "show igmp interface" in namespace "r2" should eventually contain "Non-Querier"

    # h1 joins 239.1.1.1 (kernel sends an IGMPv3 report to 224.0.0.22);
    # r1 learns the group in EXCLUDE (any-source) mode.
    When I spawn "timeout 120 socat -u UDP4-RECV:5001,ip-add-membership=239.1.1.1:eth4 /dev/null" in namespace "h1"
    Then show command "show igmp groups" in namespace "r1" should eventually contain "239.1.1.1"
    And show command "show igmp groups" in namespace "r1" should contain "EXCLUDE"

  Scenario: Teardown topology
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "h1"
    Then the test environment should be clean
