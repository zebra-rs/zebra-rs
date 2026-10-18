@pim6_rpf_neighbor
Feature: A PIMv6 Join names the upstream router by its Hello source
  r2 reaches the source through r1's global address, a static route's
  nexthop. RFC 7761 sends the Join to RPF'(S,G) = NBR(RPF interface,
  nexthop): the primary address, the Hello source, of the neighbor that
  owns the nexthop, which for PIMv6 is its link-local. r2 used to name
  the global in the Join's Upstream Neighbor field and in `show pim
  ipv6 upstream`. r1, a zebra-rs, accepts any of its addresses, but FRR
  takes a Join naming anything but its primary as one addressed to
  another router, and never joins the tree.

  r1's link-local is fixed so that the address can be matched.

  Test Topology:
  ```
    r1 eth1 ------------------ eth2 r2 eth5 ------------ eth6 h2 (receiver)
       fe80::13:1                  2001:db8:15::1
       2001:db8:13::1/64           2001:db8:13::2/64
    r1 eth3 (dummy, 2001:db8:14::1/64, the source's subnet)
  ```

  Scenario: r2 joins the (S,G) tree through r1
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "h2"
    And I connect namespace "r1" interface "eth1" to namespace "r2" interface "eth2"
    And I connect namespace "r2" interface "eth5" to namespace "h2" interface "eth6"
    And I execute "ip link set eth1 addrgenmode none" in namespace "r1"
    And I execute "ip -6 addr flush dev eth1 scope link" in namespace "r1"
    And I execute "ip -6 addr add fe80::13:1/64 dev eth1 nodad" in namespace "r1"
    And I execute "ip link add eth3 type dummy" in namespace "r1"
    And I execute "ip link set eth3 up" in namespace "r1"
    And I spawn "timeout 120 tcpdump -i eth1 -nn -U -w /tmp/pim6_rpf_neighbor.pcap pim" in namespace "r1"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I add address "2001:db8:15::2/64" to interface "eth6" in namespace "h2"
    Then show command "show pim ipv6 neighbor" in namespace "r2" should eventually contain "fe80::13:1"
    When I spawn "timeout 120 python3 tests/scripts/ssm_recv6.py ff3e::1 2001:db8:14::2 eth6 5001 /tmp/pim6_rpf_neighbor_rx" in namespace "h2"
    Then show command "show pim ipv6 upstream" in namespace "r2" should eventually contain "Joined"
    And show command "show pim ipv6 mroute" in namespace "r1" should eventually contain "ff3e::1"

  Scenario: The Join names r1's link-local
    Given the test topology exists
    Then command "tcpdump -r /tmp/pim6_rpf_neighbor.pcap -nn -v" in namespace "r1" should eventually contain "upstream-neighbor: fe80::13:1"
    And command "tcpdump -r /tmp/pim6_rpf_neighbor.pcap -nn -v" in namespace "r1" should not contain "upstream-neighbor: 2001:db8:13::1"

  Scenario: show pim ipv6 upstream names r1's link-local
    Given the test topology exists
    Then show command "show pim ipv6 upstream" in namespace "r2" should contain "fe80::13:1"

  Scenario: Teardown topology
    Given the test topology exists
    When I execute "rm -f /tmp/pim6_rpf_neighbor_rx /tmp/pim6_rpf_neighbor.pcap" in namespace "h2"
    And I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "h2"
    Then the test environment should be clean
