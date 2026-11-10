@serial
@ra_host
Feature: RA host on WAN interfaces (interface ipv6 address autoconf)

  `interface <if> ipv6 address autoconf` runs the RA host in the nd task
  (docs/design/dhcp-client.md §7): it sends Router Solicitations, and turns
  the Router Advertisements it hears into a default route, on-link prefixes
  and SLAAC addresses, all through the RIB. The routes are `A` routes at
  distance 210, installed as `proto ra`; the kernel's own RA processing is
  turned off on the interface (`accept_ra` 0).

  Topology: two upstream routers, each on its own WAN interface of r1.

      s1 (zebra-rs, RA sender) srv0 fe80::1 ──── wan0 r1 (zebra-rs, autoconf)
      s2 (tests/scripts/ra_sender.py) srv1 fe80::2 ──── wan1 r1
                                       2001:db8:1::1/64

  s1 advertises itself with zebra-rs's own RA sender (router lifetime
  1800 s, no prefix). s2 sends exactly the RAs a scenario asks for, so
  lifetimes, flags and preferences can be driven step by step. Each router
  sends from a pinned link-local, and wan1 has a fixed MAC, so the default
  route's gateways and the SLAAC address are known in advance.

  Config files:
  - s1.yaml: `send-advertisements` on srv0.
  - r1.yaml: `address autoconf` on wan0 and wan1.

  Scenario: Setup two upstream routers and an RA host
    Given a clean test environment
    When I create namespace "s1"
    And I create namespace "s2"
    And I create namespace "r1"
    And I connect namespace "s1" interface "srv0" to namespace "r1" interface "wan0"
    And I connect namespace "s2" interface "srv1" to namespace "r1" interface "wan1"
    And I execute "ip addr add fe80::1/64 dev srv0 nodad" in namespace "s1"
    And I execute "ip addr add fe80::2/64 dev srv1 nodad" in namespace "s2"
    And I execute "ip addr add 2001:db8:1::1/64 dev srv1 nodad" in namespace "s2"
    And I execute "ip link set wan1 address 52:54:00:12:34:56" in namespace "r1"
    And I start zebra-rs in namespace "s1"
    And I apply config "s1.yaml" to namespace "s1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then show command "show ipv6 nd interface wan0" in namespace "r1" should eventually contain "RA host: enabled (autoconf)"

  Scenario: The kernel's own RA processing is off on the host's interfaces
    Given the test topology exists
    Then command "cat /proc/sys/net/ipv6/conf/wan0/accept_ra" in namespace "r1" should eventually contain "0"
    And command "cat /proc/sys/net/ipv6/conf/wan1/accept_ra" in namespace "r1" should eventually contain "0"
    And command "cat /proc/sys/net/ipv6/conf/wan1/autoconf" in namespace "r1" should eventually contain "0"

  Scenario: Solicitations nobody answers stop after three
    Given the test topology exists
    # s2 sends nothing until told to. Being a host, it does not listen on
    # all-routers either, so only r1's own counters can tell.
    Then show command "show ipv6 nd interface wan1" in namespace "r1" should eventually contain "router solicitations sent 3, done"
    And show command "show ipv6 nd interface wan1" in namespace "r1" should contain "Router solicitations               3"

  Scenario: An upstream router's RA gives the default route
    Given the test topology exists
    Then show command "show ipv6 route" in namespace "r1" should eventually contain "::/0 [210/0] via fe80::1, wan0"
    And command "ip -6 route show default" in namespace "r1" should eventually contain "via fe80::1 dev wan0 proto ra metric 1024"
    And show command "show ipv6 nd interface wan0" in namespace "r1" should contain "fe80::1 preference medium, lifetime 1800s"

  Scenario: A prefix gives the on-link route and a SLAAC address, and a high-preference router wins
    Given the test topology exists
    When I execute "tests/scripts/ra_sender.py srv1 --source fe80::2 --preference high --prefix 2001:db8:1::/64,LA,3600,1800 --rdnss 2001:db8::53,600 --dnssl example.com,600" in namespace "s2"
    Then show command "show interface wan1" in namespace "r1" should eventually contain "2001:db8:1:0:5054:ff:fe12:3456/64 noprefixroute slaac valid-lft"
    And show command "show ipv6 route" in namespace "r1" should eventually contain "::/0 [210/0] via fe80::2, wan1"
    And show command "show ipv6 route" in namespace "r1" should contain "2001:db8:1::/64 [210/0] via ::, wan1"
    And command "ip -6 route show 2001:db8:1::/64" in namespace "r1" should eventually contain "dev wan1 proto ra metric 1024"
    And show command "show ipv6 nd interface wan1" in namespace "r1" should contain "DNS servers: 2001:db8::53"
    And show command "show ipv6 nd interface wan1" in namespace "r1" should contain "DNS search: example.com"
    And ping from "r1" to "2001:db8:1::1" should eventually succeed

  Scenario: Router lifetime 0 takes the router away and the other takes over
    Given the test topology exists
    When I execute "tests/scripts/ra_sender.py srv1 --source fe80::2 --lifetime 0" in namespace "s2"
    Then show command "show ipv6 route" in namespace "r1" should eventually contain "::/0 [210/0] via fe80::1, wan0"
    And show command "show ipv6 route" in namespace "r1" should not contain "via fe80::2"
    # The prefix and its address stay: they have lifetimes of their own.
    And show command "show interface wan1" in namespace "r1" should contain "2001:db8:1:0:5054:ff:fe12:3456/64 noprefixroute slaac"
    And show command "show ipv6 route" in namespace "r1" should contain "2001:db8:1::/64 [210/0] via ::, wan1"

  Scenario: ra-options orders the two interfaces by distance
    Given the test topology exists
    When I apply command "set interface wan0 ipv6 ra-options default-route-distance 220" in namespace "r1"
    Then show command "show ipv6 route" in namespace "r1" should eventually contain "::/0 [220/0] via fe80::1, wan0"
    When I execute "tests/scripts/ra_sender.py srv1 --source fe80::2" in namespace "s2"
    Then show command "show ipv6 route" in namespace "r1" should eventually contain "::/0 [210/0] via fe80::2, wan1"
    And show command "show ipv6 route" in namespace "r1" should not contain "via fe80::1"
    When I apply command "set interface wan1 ipv6 ra-options no-default-route" in namespace "r1"
    Then show command "show ipv6 route" in namespace "r1" should eventually contain "::/0 [220/0] via fe80::1, wan0"
    When I apply command "delete interface wan1 ipv6 ra-options no-default-route" in namespace "r1"
    Then show command "show ipv6 route" in namespace "r1" should eventually contain "::/0 [210/0] via fe80::2, wan1"

  Scenario: A restarted zebra-rs takes its RA routes back from the kernel
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    # The routes outlive the daemon, as the kernel holds them.
    Then command "ip -6 route show default" in namespace "r1" should eventually contain "proto ra"
    When I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply command "set interface wan0 ipv6 ra-options default-route-distance 220" in namespace "r1"
    And I execute "tests/scripts/ra_sender.py srv1 --source fe80::2 --prefix 2001:db8:1::/64,LA,3600,1800" in namespace "s2"
    Then show command "show ipv6 route" in namespace "r1" should eventually contain "A  *> ::/0 [210/0] via fe80::2, wan1"
    And show command "show ipv6 route" in namespace "r1" should not contain "K  *> ::/0"
    # The SLAAC address read back from the kernel brought a connected
    # route until the RA host claimed it again; the on-link route is the
    # RA host's own.
    And show command "show ipv6 route" in namespace "r1" should eventually contain "A  *> 2001:db8:1::/64 [210/0] via ::, wan1"
    And show command "show ipv6 route" in namespace "r1" should not contain "C  *> 2001:db8:1::/64"

  Scenario: Deleting autoconf withdraws the address and the routes
    Given the test topology exists
    When I apply command "delete interface wan1 ipv6 address autoconf" in namespace "r1"
    Then show command "show interface wan1" in namespace "r1" should eventually not contain "2001:db8:1:0:5054:ff:fe12:3456"
    And show command "show ipv6 route" in namespace "r1" should eventually not contain "2001:db8:1::/64"
    And show command "show ipv6 route" in namespace "r1" should eventually contain "::/0 [220/0] via fe80::1, wan0"
    And command "ip -6 route show proto ra" in namespace "r1" should eventually not contain "wan1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "s1"
    And I delete namespace "r1"
    And I delete namespace "s2"
    And I delete namespace "s1"
    Then the test environment should be clean
