@rib_nexthop_leftover
Feature: Next-hop objects an earlier run left in the kernel
  A run of zebra-rs that stops without withdrawing its routes, a crash
  say, leaves them in the kernel with the next-hop objects they forward
  through. The next run keeps those objects' ids from its own (#2463) and
  replaces or sweeps the routes. Once the leftover sweep is done, it
  deletes the objects nothing names any more; they used to stay for good.
  One a route still forwards through is kept, as deleting it would take
  the route with it, and so are a kept group's members.

  Test Topology (z1 alone; the gateways named are on its subnet):
  ```
   z1 (vz1ns 192.168.0.1/24) ── br0
  ```

  Scenario: A crashed run's objects go once nothing forwards through them
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I apply command "set router static ipv4 route 10.1.0.0/24 nexthop 192.168.0.2" in namespace "z1"
    And I apply command "set router static ipv4 route 10.2.0.0/24 nexthop 192.168.0.3" in namespace "z1"
    And I apply command "set router static ipv4 route 10.2.0.0/24 nexthop 192.168.0.4" in namespace "z1"
    Then command "ip route show 10.2.0.0/24" in namespace "z1" should eventually contain "nhid"
    And command "ip nexthop show" in namespace "z1" should eventually contain "group"
    # A crash: the daemon goes, its routes and objects stay in the kernel.
    When I stop zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z1" sweeping leftovers after 15 seconds
    And I apply command "set router static ipv4 route 10.1.0.0/24 nexthop 192.168.0.2" in namespace "z1"
    Then the zebra-rs log in namespace "z1" should contain "4 next-hop object(s) of an earlier run found"
    And command "ip route show 10.1.0.0/24" in namespace "z1" should eventually contain "192.168.0.2"
    # 10.1.0.0/24 now forwards through an object of this run, and
    # 10.2.0.0/24, which this configuration does not have, is swept. Its
    # group and their members, and 10.1.0.0/24's old object, go with it.
    And command "ip route show" in namespace "z1" should eventually not contain "10.2.0.0/24"
    And command "ip nexthop show" in namespace "z1" should eventually not contain "192.168.0.3"
    And command "ip nexthop show" in namespace "z1" should not contain "192.168.0.4"
    And command "ip nexthop show" in namespace "z1" should not contain "group"
    And command "ip route show 10.1.0.0/24" in namespace "z1" should eventually contain "192.168.0.2"
    When I wait 2 seconds
    Then the zebra-rs log in namespace "z1" should contain "removed 4 next-hop object(s) an earlier run left"

  Scenario: An object a route still forwards through is kept, with its group's members
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    # The earlier run's (proto zebra): a group a route forwards through,
    # and an unused one, each with members; and an object of another's.
    And I execute "ip nexthop add id 500 via 192.168.0.9 dev vz1ns proto zebra" in namespace "z1"
    And I execute "ip nexthop add id 501 via 192.168.0.8 dev vz1ns proto zebra" in namespace "z1"
    And I execute "ip nexthop add id 502 via 192.168.0.7 dev vz1ns proto zebra" in namespace "z1"
    And I execute "ip nexthop add id 503 group 500/502 proto zebra" in namespace "z1"
    And I execute "ip nexthop add id 504 group 501 proto zebra" in namespace "z1"
    And I execute "ip nexthop add id 505 via 192.168.0.6 dev vz1ns" in namespace "z1"
    # A main-table BGP route is another daemon's: it is never swept.
    And I execute "ip route add 10.9.0.0/24 nhid 503 proto bgp" in namespace "z1"
    And I start zebra-rs in namespace "z1" sweeping leftovers after 15 seconds
    Then command "ip nexthop show" in namespace "z1" should eventually not contain "id 504 "
    And command "ip nexthop show" in namespace "z1" should not contain "id 501 "
    And command "ip nexthop show" in namespace "z1" should eventually contain "id 503 "
    And command "ip nexthop show" in namespace "z1" should eventually contain "id 500 "
    And command "ip nexthop show" in namespace "z1" should eventually contain "id 502 "
    And command "ip nexthop show" in namespace "z1" should eventually contain "id 505 "
    And command "ip route show 10.9.0.0/24" in namespace "z1" should eventually contain "nhid 503"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete bridge "br0"
    Then the test environment should be clean
