@serial
@pim6_vrf
Feature: PIMv6 SSM forwarding inside a VRF
  As a network operator
  I want `router pim vrf <name> ipv6` to run a full per-VRF PIMv6
  instance — sockets bound into the VRF, the kernel MRT6 table selected
  with MRT6_TABLE, MLD and Join/Prune state scoped to the VRF — so IPv6
  multicast in one VRF neither sees nor disturbs the default table.

  Same shape as the pim6_ssm feature, but every router interface is
  enslaved to VRF mvrf and all PIMv6/MLD config lives under
  `router pim vrf mvrf ipv6`. The parent's per-VRF Pim<Ipv4> child spawns
  a per-VRF Pim<Ipv6> grandchild; the default IPv6 instance is never
  configured and must stay absent.

  Test Topology (all router interfaces in VRF mvrf):
  ```
    h1 (2001:db8:14::10, sender) --- eth4/eth3 --- r1 --- eth1/eth2 --- r2 --- eth5/eth6 --- h2 (2001:db8:15::10, receiver)
                                       2001:db8:14::1   2001:db8:13::1/.2       2001:db8:15::1
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
    And I add address "2001:db8:14::10/64" to interface "eth4" in namespace "h1"
    And I add address "2001:db8:15::10/64" to interface "eth6" in namespace "h2"

    # The per-VRF IPv6 grandchild converges inside the VRF, and the
    # default IPv6 instance (never configured) stays empty — isolation.
    Then show command "show pim vrf mvrf ipv6 neighbor" in namespace "r2" should eventually contain "fe80"
    And show command "show pim ipv6 neighbor" in namespace "r2" should not contain "fe80"

    # h2 source-specifically joins (2001:db8:14::10, ff3e::8) — MLD,
    # upstream join and TIB all inside the VRF.
    When I spawn "timeout 150 python3 tests/scripts/ssm_recv6.py ff3e::8 2001:db8:14::10 eth6 5001 /tmp/pim6_vrf_rx" in namespace "h2"
    Then show command "show pim vrf mvrf ipv6 mld groups" in namespace "r2" should eventually contain "ff3e::8"
    And show command "show pim vrf mvrf ipv6 upstream" in namespace "r2" should eventually contain "Joined"
    And show command "show pim vrf mvrf ipv6 mroute" in namespace "r2" should eventually contain "ff3e::8"
    And show command "show pim vrf mvrf ipv6 mroute" in namespace "r1" should eventually contain "ff3e::8"

    # Kernel MRT6 MFCs live in the VRF's multicast table.
    And command "ip -6 mroute show table all" in namespace "r1" should eventually contain "Iif: eth3"
    And command "ip -6 mroute show table all" in namespace "r2" should eventually contain "Iif: eth2"

    # The datapath proof: h1's datagrams reach h2 through both VRF
    # forwarding caches.
    When I spawn "timeout 120 python3 tests/scripts/mcast_send6.py ff3e::8 5001 eth4 90" in namespace "h1"
    Then command "cat /tmp/pim6_vrf_rx" in namespace "h2" should eventually contain "ssm-hello"

  Scenario: Teardown topology
    When I execute "rm -f /tmp/pim6_vrf_rx" in namespace "h2"
    And I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "h1"
    And I delete namespace "h2"
    Then the test environment should be clean
