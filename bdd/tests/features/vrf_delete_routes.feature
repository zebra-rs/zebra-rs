@serial
@vrf_delete_routes
Feature: Deleting a VRF takes its routes out of the kernel

  When a VRF device is deleted, the kernel removes the routes through
  the VRF's own interfaces along with it, and no others. A route in the
  VRF's table that has no interface (a static `nexthop blackhole`), or
  one through an interface outside the VRF, stays in the table, and
  the next VRF given that table id would inherit it. So zebra-rs
  withdraws what it installed in a VRF's table before the VRF goes:
  when the VRF is deleted, and when zebra-rs stops and takes the VRF
  devices it created with it.

  Table ids are handed out lowest first, so the VRF created after the
  only one is deleted gets the id that one had: 1.

  Topology: r is zebra-rs with one interface in VRF blue.

      r lan0 (vrf blue) 192.0.2.1, 2001:db8:1::1 ---- eth0 h

  Config files:
  - r.yaml: VRF blue with lan0 in it, and in the VRF two discard routes and two routes through lan0.
  - r_none.yaml: no VRF and no static route.
  - r_red.yaml: another VRF, red, with nothing in it.

  Scenario: Setup a router with a VRF and static routes in it
    Given a clean test environment
    When I create namespace "r"
    And I create namespace "h"
    And I connect namespace "r" interface "lan0" to namespace "h" interface "eth0"
    And I start zebra-rs in namespace "r"
    And I apply config "r.yaml" to namespace "r"
    Then command "ip -d link show blue" in namespace "r" should eventually contain "vrf table 1 "
    And command "ip route show vrf blue" in namespace "r" should eventually contain "blackhole 10.9.9.0/24 proto zebra"
    And command "ip route show vrf blue" in namespace "r" should eventually contain "via 192.0.2.2 dev lan0 proto zebra"
    And command "ip -6 route show vrf blue" in namespace "r" should eventually contain "blackhole 2001:db8:dead::/48"
    And command "ip -6 route show vrf blue" in namespace "r" should eventually contain "via 2001:db8:1::2 dev lan0 proto zebra"
    And show command "show ip route vrf blue" in namespace "r" should eventually contain "10.9.9.0/24 [1/0] is a discard (blackhole)"

  Scenario: The VRF goes, and its routes with it
    Given the test topology exists
    When I apply config "r_none.yaml" to namespace "r"
    Then command "ip -br link show" in namespace "r" should eventually not contain "blue"
    # The kernel took the routes through lan0 with the device. The
    # discard routes have no interface for it to go by.
    And command "ip route show table all" in namespace "r" should eventually not contain "10.9.9.0/24"
    And command "ip -6 route show table all" in namespace "r" should eventually not contain "2001:db8:dead::/48"
    And command "ip route show table all" in namespace "r" should eventually not contain "10.8.0.0/16"
    And command "ip -6 route show table all" in namespace "r" should eventually not contain "2001:db8:8::/48"

  Scenario: Another VRF given the table id starts with none of them
    Given the test topology exists
    When I apply config "r_red.yaml" to namespace "r"
    Then command "ip -d link show red" in namespace "r" should eventually contain "vrf table 1 "
    And command "ip route show table all" in namespace "r" should not contain "10.9.9.0/24"
    And command "ip -6 route show table all" in namespace "r" should not contain "2001:db8:dead::/48"
    And show command "show ip route vrf red" in namespace "r" should not contain "10.9.9.0/24"

  Scenario: The VRF comes back with its routes
    Given the test topology exists
    # Its configuration is applied again: nothing left of the first
    # time stands in the way of the routes.
    When I apply config "r.yaml" to namespace "r"
    Then command "ip -br link show" in namespace "r" should eventually not contain "red"
    And command "ip route show vrf blue" in namespace "r" should eventually contain "blackhole 10.9.9.0/24 proto zebra"
    And command "ip route show vrf blue" in namespace "r" should eventually contain "via 192.0.2.2 dev lan0 proto zebra"
    And command "ip -6 route show vrf blue" in namespace "r" should eventually contain "blackhole 2001:db8:dead::/48"
    And command "ip -6 route show vrf blue" in namespace "r" should eventually contain "via 2001:db8:1::2 dev lan0 proto zebra"
    And show command "show ip route vrf blue" in namespace "r" should eventually contain "10.9.9.0/24 [1/0] is a discard (blackhole)"

  Scenario: Stopping zebra-rs takes the VRF it created, and its routes
    Given the test topology exists
    # Stopped as systemd stops it (SIGINT), zebra-rs deletes the VRF
    # devices it created. Nothing would take the discard routes over
    # after a restart, when the table id may be another VRF's: they go
    # as well.
    When I execute "tests/scripts/sigint_pidfile.sh /tmp/vrf_delete_routes_r.pid" in namespace "r"
    Then command "ip -br link show" in namespace "r" should eventually not contain "blue"
    And command "ip route show table all" in namespace "r" should eventually not contain "10.9.9.0/24"
    And command "ip -6 route show table all" in namespace "r" should eventually not contain "2001:db8:dead::/48"
    # Started again with another VRF and no route: no table has them.
    When I start zebra-rs in namespace "r"
    And I apply config "r_red.yaml" to namespace "r"
    Then command "ip -br link show" in namespace "r" should eventually contain "red"
    And command "ip route show table all" in namespace "r" should not contain "10.9.9.0/24"
    And command "ip -6 route show table all" in namespace "r" should not contain "2001:db8:dead::/48"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r"
    And I delete namespace "r"
    And I delete namespace "h"
    Then the test environment should be clean
