@serial
@dhcpv6_client_pd_lan
Feature: Interfaces numbered from a delegated prefix (dhcpv6-options pd <id> interface)

  `interface <wan> ipv6 dhcpv6-options pd <id> interface <lan>` gives
  `<lan>` an address in one /64 of the prefix delegated to `<wan>`
  (docs/design/dhcp-client.md §8): the /64 its `sla-id` numbers, the
  first when it has none, and in it the host part `address` names, or
  one made from the interface's hardware address (EUI-64).

  The address has the prefix's lifetimes and follows the lease: a
  renewal moves its lifetimes, another prefix replaces it, and it goes
  when the prefix is given back. Unlike a leased address it brings the
  route to its /64, which is what takes that part of the prefix off the
  unreachable route the whole of it has (dhcpv6_client_pd.feature).

  Topology: s1 is the ISP side, a router with the small DHCPv6 server of
  dhcpv6_client_pd.feature, which routes what it delegates to the
  client. r1 is zebra-rs: a DHCPv6 WAN, and two interfaces behind it.
  h1 is a host on the first, numbered by hand in the /64 that interface
  gets; lan1 leads nowhere.

      s1 (dhcpv6_server.py) srv0 fe80::1 ──── wan0 r1 lan0 ──── eth0 h1
         lo 2001:db8:ffff::1/128             (pd 1)  lan1 (a dummy)
         pd 1 = 2001:db8:100::/56, later 2001:db8:900::/56

  Requires python3 on the host.

  Config files:
  - r1.yaml: `address dhcpv6` and `pd 1 length 56` on wan0, with `interface lan0 sla-id 1 address 1` and `interface lan1 sla-id 2`.
  - r1_lan0.yaml: the same without lan1.

  Scenario: Setup the delegating router, a router with two interfaces behind it, and a host
    Given a clean test environment
    When I create namespace "s1"
    And I create namespace "r1"
    And I create namespace "h1"
    And I connect namespace "s1" interface "srv0" to namespace "r1" interface "wan0"
    And I connect namespace "r1" interface "lan0" to namespace "h1" interface "eth0"
    And I execute "ip link add lan1 address 02:00:00:00:00:b1 type dummy" in namespace "r1"
    And I execute "ip link set lan1 up" in namespace "r1"
    And I execute "sysctl -q -w net.ipv6.conf.all.forwarding=1" in namespace "r1"
    And I execute "ip addr add fe80::1/64 dev srv0 nodad" in namespace "s1"
    And I execute "ip link set lo up" in namespace "s1"
    And I execute "ip -6 addr add 2001:db8:ffff::1/128 dev lo" in namespace "s1"
    And I execute "sysctl -q -w net.ipv6.conf.all.forwarding=1" in namespace "s1"
    And I execute "ip -6 addr add 2001:db8:100:1::10/64 dev eth0 nodad" in namespace "h1"
    And I execute "ip -6 route add default via 2001:db8:100:1::1" in namespace "h1"
    And I execute "tests/scripts/dhcpv6_server.py dhcpv6_client_pd_lan start srv0 --address 2001:db8:1::100 --pd 1=2001:db8:100::/56 --route" in namespace "s1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "Prefix:       2001:db8:100::/56 preferred"

  Scenario: Each interface gets its /64 of the prefix
    Given the test topology exists
    # lan0 by its `sla-id` and `address`; lan1 by its `sla-id` and its
    # hardware address, 02:00:00:00:00:b1.
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "on lan0:    2001:db8:100:1::1/64"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "on lan1:    2001:db8:100:2:0:ff:fe00:b1/64"
    And show command "show interface lan0" in namespace "r1" should eventually contain "inet6 2001:db8:100:1::1/64 dhcpv6-pd valid-lft"
    And daemon log in namespace "r1" should eventually contain "dhcpv6 client: lan0: 2001:db8:100:1::1/64 from the prefix delegated on wan0"
    # In the kernel with the prefix's lifetime, and with the route to
    # its /64, which a leased address does not bring.
    And command "ip -6 addr show dev lan0 scope global" in namespace "r1" should eventually contain "inet6 2001:db8:100:1::1/64 scope global dynamic"
    And command "ip -6 addr show dev lan1 scope global" in namespace "r1" should eventually contain "inet6 2001:db8:100:2:0:ff:fe00:b1/64 scope global dynamic"
    And command "ip -6 route show 2001:db8:100:1::/64" in namespace "r1" should eventually contain "dev lan0 proto kernel"
    And show command "show ipv6 route" in namespace "r1" should eventually contain "2001:db8:100:1::/64"
    # The rest of the prefix stays on its unreachable route.
    And command "ip -6 route show 2001:db8:100::/56" in namespace "r1" should eventually contain "unreachable 2001:db8:100::/56"

  Scenario: A host behind the router is reached through the prefix
    Given the test topology exists
    # s1 routes the prefix to r1, r1 has the /64 on lan0, and the host's
    # answer leaves by the default route the Router Advertisement gives.
    When I execute "tests/scripts/ra_sender.py srv0 --source fe80::1" in namespace "s1"
    Then show command "show ipv6 route" in namespace "r1" should eventually contain "::/0 [210/0] via fe80::1"
    And command "ip -6 route show 2001:db8:100::/56" in namespace "s1" should eventually contain "via fe80::"
    And command "tests/scripts/ping6_once.sh 2001:db8:100:1::10 2001:db8:ffff::1" in namespace "s1" should eventually contain "1 received"
    # A part of the prefix no interface has: the host hears at once that
    # nothing is there (RFC 7084 WPD-5), where a packet for anything
    # outside the prefix takes the default route.
    And command "tests/scripts/ping6_once.sh 2001:db8:100:ff::1" in namespace "h1" should eventually contain "From 2001:db8:100:1::1 icmp_seq=1 Destination unreachable: No route"
    And command "tests/scripts/ping6_once.sh 2001:db8:ffff::1" in namespace "h1" should eventually contain "1 received"

  Scenario: A link set down and up has its address again
    Given the test topology exists
    # The kernel takes an interface's IPv6 addresses away with the link.
    When I execute "ip link set lan0 down" in namespace "r1"
    Then command "ip -6 addr show dev lan0" in namespace "r1" should eventually not contain "2001:db8:100:1::1/64"
    When I execute "ip link set lan0 up" in namespace "r1"
    Then command "ip -6 addr show dev lan0 scope global" in namespace "r1" should eventually contain "inet6 2001:db8:100:1::1/64 scope global dynamic"
    And command "ip -6 route show 2001:db8:100:1::/64" in namespace "r1" should eventually contain "dev lan0 proto kernel"
    And command "tests/scripts/ping6_once.sh 2001:db8:100:1::10 2001:db8:ffff::1" in namespace "s1" should eventually contain "1 received"

  Scenario: A renewal moves the lifetimes of the addresses
    Given the test topology exists
    # The server comes back with other lifetimes and no record of the
    # lease: the Renew is told NoBinding, the Request that follows is
    # answered, and the lease's new times are the addresses' too.
    When I execute "tests/scripts/dhcpv6_server.py dhcpv6_client_pd_lan stop" in namespace "s1"
    And I execute "tests/scripts/dhcpv6_server.py dhcpv6_client_pd_lan start srv0 --address 2001:db8:1::100 --pd 1=2001:db8:100::/56 --route --preferred 30000 --valid 60000" in namespace "s1"
    Then show command "renew dhcpv6 interface wan0" in namespace "r1" should contain "Renewing the DHCPv6 lease on wan0"
    And command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client_pd_lan/server.log" in namespace "s1" should eventually contain "REQUEST ia_na"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"
    # 60000 s counting down, where it was at most 7200 s.
    And command "ip -6 addr show dev lan0 scope global" in namespace "r1" should eventually contain "valid_lft 59"
    And command "ip -6 addr show dev lan1 scope global" in namespace "r1" should eventually contain "valid_lft 59"

  Scenario: Another prefix replaces the addresses
    Given the test topology exists
    When I execute "tests/scripts/dhcpv6_server.py dhcpv6_client_pd_lan stop" in namespace "s1"
    And I execute "tests/scripts/dhcpv6_server.py dhcpv6_client_pd_lan start srv0 --address 2001:db8:1::100 --pd 1=2001:db8:900::/56 --route --preferred 30000 --valid 60000" in namespace "s1"
    Then show command "renew dhcpv6 interface wan0" in namespace "r1" should contain "Renewing the DHCPv6 lease on wan0"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "Prefix:       2001:db8:900::/56 preferred"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually not contain "2001:db8:100::/56"
    # The unreachable route and both addresses are the new prefix's.
    And command "ip -6 route show 2001:db8:900::/56" in namespace "r1" should eventually contain "unreachable 2001:db8:900::/56"
    And kernel route "2001:db8:100::/56" in namespace "r1" should eventually be gone
    And command "ip -6 addr show dev lan0 scope global" in namespace "r1" should eventually contain "inet6 2001:db8:900:1::1/64 scope global dynamic"
    And command "ip -6 addr show dev lan0" in namespace "r1" should eventually not contain "2001:db8:100:1::1"
    And command "ip -6 addr show dev lan1 scope global" in namespace "r1" should eventually contain "inet6 2001:db8:900:2:0:ff:fe00:b1/64 scope global dynamic"
    And command "ip -6 addr show dev lan1" in namespace "r1" should eventually not contain "2001:db8:100:2:"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "on lan0:    2001:db8:900:1::1/64"

  Scenario: The interfaces follow the configuration, and the prefix stays
    Given the test topology exists
    # Another /64 for lan1.
    When I apply command "set interface wan0 ipv6 dhcpv6-options pd 1 interface lan1 sla-id 3" in namespace "r1"
    Then command "ip -6 addr show dev lan1 scope global" in namespace "r1" should eventually contain "inet6 2001:db8:900:3:0:ff:fe00:b1/64 scope global dynamic"
    And command "ip -6 addr show dev lan1" in namespace "r1" should eventually not contain "2001:db8:900:2:"
    # A /64 the /56 does not have: the interface is left without an
    # address, and that is said.
    When I apply command "set interface wan0 ipv6 dhcpv6-options pd 1 interface lan1 sla-id 300" in namespace "r1"
    Then command "ip -6 addr show dev lan1" in namespace "r1" should eventually not contain "2001:db8:900:"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "on lan1:    none (the prefix has no room for this sla-id)"
    And daemon log in namespace "r1" should eventually contain "pd 1 interface lan1 gets no address from 2001:db8:900::/56"
    # Two interfaces on one /64, and the interface the prefix is
    # delegated on, are refused.
    Then applying command "set interface wan0 ipv6 dhcpv6-options pd 1 interface lan1 sla-id 1" in namespace "r1" should be rejected with "have the same sla-id 1"
    And applying command "set interface wan0 ipv6 dhcpv6-options pd 1 interface wan0 sla-id 9" in namespace "r1" should be rejected with "cannot number the interface it is delegated on"
    When I apply command "set interface wan0 ipv6 dhcpv6-options pd 1 interface lan1 sla-id 2" in namespace "r1"
    Then command "ip -6 addr show dev lan1 scope global" in namespace "r1" should eventually contain "inet6 2001:db8:900:2:0:ff:fe00:b1/64 scope global dynamic"
    # None of it is asked of the server: the lease is what it was.
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "State:        bound"
    And command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client_pd_lan/server.log" in namespace "s1" should not contain "RELEASE"
    And command "ip -6 addr show dev lan0 scope global" in namespace "r1" should eventually contain "inet6 2001:db8:900:1::1/64 scope global dynamic"

  Scenario: A restart keeps the addresses, and removes one that is configured no longer
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    # Both stay in the kernel while zebra-rs is down.
    Then command "ip -6 addr show dev lan0 scope global" in namespace "r1" should eventually contain "inet6 2001:db8:900:1::1/64"
    And command "ip -6 addr show dev lan1 scope global" in namespace "r1" should eventually contain "inet6 2001:db8:900:2:0:ff:fe00:b1/64"
    When I start zebra-rs in namespace "r1"
    And I apply config "r1_lan0.yaml" to namespace "r1"
    Then daemon log in namespace "r1" should eventually contain "dhcpv6 client: wan0: resumed 2001:db8:1::100, 2001:db8:900::/56"
    # lan1 is not in the configuration any more: the lease file names
    # the address it was given, and it is removed.
    And daemon log in namespace "r1" should eventually contain "dhcpv6 client: lan1: 2001:db8:900:2:0:ff:fe00:b1/64 of an earlier lease removed"
    And command "ip -6 addr show dev lan1" in namespace "r1" should eventually not contain "2001:db8:900:2:"
    And command "ip -6 addr show dev lan0 scope global" in namespace "r1" should eventually contain "inet6 2001:db8:900:1::1/64 scope global dynamic"
    And show command "show interface lan0" in namespace "r1" should eventually contain "inet6 2001:db8:900:1::1/64 dhcpv6-pd valid-lft"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "State:        bound"

  Scenario: Deleted configuration gives the prefix back and takes the addresses
    Given the test topology exists
    # An interface taken out of the delegation alone: the prefix stays.
    When I apply command "delete interface wan0 ipv6 dhcpv6-options pd 1 interface lan0" in namespace "r1"
    Then command "ip -6 addr show dev lan0" in namespace "r1" should eventually not contain "2001:db8:900:1::1"
    And show command "show dhcpv6 client leases" in namespace "r1" should contain "Prefix:       2001:db8:900::/56 preferred"
    When I apply command "set interface wan0 ipv6 dhcpv6-options pd 1 interface lan0 sla-id 1" in namespace "r1"
    And I apply command "set interface wan0 ipv6 dhcpv6-options pd 1 interface lan0 address 1" in namespace "r1"
    Then command "ip -6 addr show dev lan0 scope global" in namespace "r1" should eventually contain "inet6 2001:db8:900:1::1/64 scope global dynamic"
    # The delegation itself: the prefix goes back to the server, and
    # what it numbered goes with it.
    When I apply command "delete interface wan0 ipv6 dhcpv6-options pd 1" in namespace "r1"
    Then command "cat /tmp/zebra-bdd-dhcp/dhcpv6_client_pd_lan/server.log" in namespace "s1" should eventually contain "RELEASE ia_na"
    And command "ip -6 addr show dev lan0" in namespace "r1" should eventually not contain "2001:db8:900:1::1"
    And kernel route "2001:db8:900::/56" in namespace "r1" should eventually be gone
    And command "ip -6 route show 2001:db8:900:1::/64" in namespace "r1" should eventually not contain "dev lan0"
    And daemon log in namespace "r1" should eventually contain "dhcpv6 client: lan0: 2001:db8:900:1::1/64 withdrawn"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcpv6_server.py dhcpv6_client_pd_lan stop" in namespace "s1"
    And I delete namespace "h1"
    And I delete namespace "r1"
    And I delete namespace "s1"
    Then the test environment should be clean
