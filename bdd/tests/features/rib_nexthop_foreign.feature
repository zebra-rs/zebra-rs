@rib_nexthop_foreign
Feature: Next-hop objects another program makes while zebra-rs runs
  zebra-rs installs each next-hop group as a kernel object whose id is the
  group's gid, with NLM_F_REPLACE. It keeps the ids of the objects the
  kernel holds at startup from its groups. Another program, an operator or
  systemd-networkd say, can make one later. Its id used to be handed to
  the next group, whose install then took the object over: the program's
  routes forwarded through our next hop. A gid freed when its last route
  went was given back to the same next hop when it returned, whatever had
  taken that id meanwhile.

  Test Topology (z1 alone; the gateways named are on its subnet):
  ```
   z1 (vz1ns 192.168.0.1/24) ── br0
  ```

  Scenario: An object made while zebra-rs runs keeps its id
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I apply command "set router static ipv4 route 10.1.0.0/24 nexthop 192.168.0.2" in namespace "z1"
    Then command "ip route show 10.1.0.0/24" in namespace "z1" should eventually contain "nhid 1 "
    # Another program's objects, with the ids the next groups would get.
    When I execute "ip nexthop add id 2 blackhole" in namespace "z1"
    And I execute "ip nexthop add id 3 blackhole" in namespace "z1"
    And I apply command "set router static ipv4 route 10.2.0.0/24 nexthop 192.168.0.3" in namespace "z1"
    Then command "ip route show 10.2.0.0/24" in namespace "z1" should eventually contain "nhid 4 "
    And command "ip nexthop show id 2" in namespace "z1" should eventually contain "blackhole"
    And command "ip nexthop show id 3" in namespace "z1" should eventually contain "blackhole"

  Scenario: A freed gid another program took is not given back
    Given the test topology exists
    # A fresh run with no object in the kernel: its gids start at 1.
    When I stop zebra-rs in namespace "z1"
    And I execute "ip nexthop flush" in namespace "z1"
    And I start zebra-rs in namespace "z1"
    And I apply command "set router static ipv4 route 10.3.0.0/24 nexthop 192.168.0.4" in namespace "z1"
    Then command "ip route show 10.3.0.0/24" in namespace "z1" should eventually contain "nhid 1 "
    # The route goes, and its group and object with it; another program
    # takes the id.
    When I apply command "delete router static ipv4 route 10.3.0.0/24" in namespace "z1"
    Then command "ip nexthop show" in namespace "z1" should eventually not contain "id 1 "
    When I execute "ip nexthop add id 1 blackhole" in namespace "z1"
    And I apply command "set router static ipv4 route 10.3.0.0/24 nexthop 192.168.0.4" in namespace "z1"
    Then command "ip route show 10.3.0.0/24" in namespace "z1" should eventually contain "nhid 2 "
    And command "ip nexthop show id 1" in namespace "z1" should eventually contain "blackhole"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete bridge "br0"
    Then the test environment should be clean
