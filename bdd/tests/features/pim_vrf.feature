@serial
@pim_vrf
Feature: PIM SSM forwarding inside a VRF
  As a network operator
  I want `router pim vrf <name>` to run a full per-VRF PIM instance —
  sockets bound into the VRF, the kernel multicast table selected
  with MRT_TABLE, IGMP and Join/Prune state scoped to the VRF — so
  multicast in one VRF neither sees nor disturbs the default table.

  Same shape as the pim_ssm feature, but every router interface is
  enslaved to VRF mvrf and all PIM/IGMP config lives under
  `router pim vrf mvrf`. The default PIM instance runs with no
  interfaces and must stay empty while the mvrf child converges.

  Test Topology (all router interfaces in VRF mvrf):
  ```
    h1 (10.8.14.10, sender) --- eth4/eth3 --- r1 --- eth1/eth2 --- r2 --- eth5/eth6 --- h2 (10.8.15.10, receiver)
                                    10.8.14.1     10.8.13.1/.2       10.8.15.1
  ```

  Scenario: SSM join builds the (S,G) tree in the VRF and traffic flows
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
    And I add address "10.8.14.10/24" to interface "eth4" in namespace "h1"
    And I add address "10.8.15.10/24" to interface "eth6" in namespace "h2"

    # The per-VRF child spawned and registered its show channel;
    # neighborship forms inside the VRF while the default instance
    # stays empty.
    Then show command "show task" in namespace "r2" should eventually contain "mvrf"
    And show command "show pim vrf mvrf neighbor" in namespace "r2" should eventually contain "10.8.13.1"
    And show command "show pim neighbor" in namespace "r2" should not contain "10.8.13.1"

    # h2 source-specifically joins (10.8.14.10, 232.8.8.8) — IGMP,
    # upstream join and TIB all inside the VRF.
    When I spawn "timeout 150 python3 tests/scripts/ssm_recv.py 232.8.8.8 10.8.14.10 10.8.15.10 5001 /tmp/pim_vrf_rx" in namespace "h2"
    Then show command "show igmp vrf mvrf groups" in namespace "r2" should eventually contain "232.8.8.8"
    And show command "show pim vrf mvrf upstream" in namespace "r2" should eventually contain "Joined"
    And show command "show mroute vrf mvrf" in namespace "r2" should eventually contain "232.8.8.8"
    And show command "show mroute vrf mvrf" in namespace "r1" should eventually contain "232.8.8.8"

    # Kernel MFCs live in the VRF's multicast table.
    And command "ip mroute show table all" in namespace "r1" should eventually contain "Iif: eth3"
    And command "ip mroute show table all" in namespace "r2" should eventually contain "Iif: eth2"

    # The datapath proof: h1's datagrams reach h2 through both VRF
    # forwarding caches.
    When I spawn "timeout 120 python3 tests/scripts/mcast_send.py 232.8.8.8 5001 10.8.14.10 90" in namespace "h1"
    Then command "cat /tmp/pim_vrf_rx" in namespace "h2" should eventually contain "ssm-hello"

  Scenario: Teardown topology
    When I execute "rm -f /tmp/pim_vrf_rx" in namespace "h2"
    And I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "h1"
    And I delete namespace "h2"
    Then the test environment should be clean
