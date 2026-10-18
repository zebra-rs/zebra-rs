@pim6_show_columns
@pim
Feature: PIMv6 and MLD show tables fit IPv6 addresses
  Every PIM show table had fixed columns sized for IPv4: 17 characters
  for an address. The tables are shared with PIMv6, where a link-local
  address is 25 characters, so it ran straight into the next column:
  `fe80::…:4402fe80::…:4402`. A column now grows to its longest cell
  plus two spaces; IPv4 output keeps the old layout.

  The link-locals are fixed, 25 characters each, so whole rows can be
  matched. The host h joins a 22-character group.

  Test Topology:
  ```
   p1 eth1 ─────────── eth2 p2 eth3 ─────────── eth4 h
      fe80::1111:2222:3333:4401  fe80::1111:2222:3333:4402
                                 fe80::1111:2222:3333:4403 (MLD querier)
  ```

  Config files:
  - p1.yaml: PIMv6 on eth1.
  - p2.yaml: PIMv6 on eth2 and eth3, MLD on eth3.

  Scenario: Build the routers with fixed link-local addresses
    Given a clean test environment
    When I create namespace "p1"
    And I create namespace "p2"
    And I create namespace "h"
    And I connect namespace "p1" interface "eth1" to namespace "p2" interface "eth2"
    And I connect namespace "p2" interface "eth3" to namespace "h" interface "eth4"
    And I execute "ip link set eth1 addrgenmode none" in namespace "p1"
    And I execute "ip -6 addr flush dev eth1 scope link" in namespace "p1"
    And I execute "ip -6 addr add fe80::1111:2222:3333:4401/64 dev eth1 nodad" in namespace "p1"
    And I execute "ip link set eth2 addrgenmode none" in namespace "p2"
    And I execute "ip -6 addr flush dev eth2 scope link" in namespace "p2"
    And I execute "ip -6 addr add fe80::1111:2222:3333:4402/64 dev eth2 nodad" in namespace "p2"
    And I execute "ip link set eth3 addrgenmode none" in namespace "p2"
    And I execute "ip -6 addr flush dev eth3 scope link" in namespace "p2"
    And I execute "ip -6 addr add fe80::1111:2222:3333:4403/64 dev eth3 nodad" in namespace "p2"
    And I start zebra-rs in namespace "p1"
    And I start zebra-rs in namespace "p2"
    And I apply config "p1.yaml" to namespace "p1"
    And I apply config "p2.yaml" to namespace "p2"
    Then show command "show pim ipv6 neighbor" in namespace "p2" should eventually contain "fe80::1111:2222:3333:4401"

  Scenario: show pim ipv6 interface keeps Address and DR apart
    Given the test topology exists
    Then show command "show pim ipv6 interface" in namespace "p2" should eventually contain "eth2         Up      fe80::1111:2222:3333:4402  fe80::1111:2222:3333:4402  1        30     1"

  Scenario: show pim ipv6 neighbor keeps Neighbor and DR Prio apart
    Given the test topology exists
    Then show command "show pim ipv6 neighbor" in namespace "p2" should eventually contain "eth2         fe80::1111:2222:3333:4401  1        "

  Scenario: show pim ipv6 mld interface keeps Querier and Address apart
    Given the test topology exists
    Then show command "show pim ipv6 mld interface" in namespace "p2" should eventually contain "eth3         Querier      fe80::1111:2222:3333:4403  fe80::1111:2222:3333:4403  "

  Scenario: show pim ipv6 mld groups keeps Group and Mode apart
    Given the test topology exists
    When I spawn "timeout 90 python3 tests/scripts/mld_join.py ff3e:1234:5678::abcd:1 eth4 85" in namespace "h"
    Then show command "show pim ipv6 mld groups" in namespace "p2" should eventually contain "eth3         ff3e:1234:5678::abcd:1  EXCLUDE  "

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "p1"
    And I stop zebra-rs in namespace "p2"
    And I delete namespace "p1"
    And I delete namespace "p2"
    And I delete namespace "h"
    Then the test environment should be clean
