@serial
@ra_prefix
Feature: Router Advertisements name the interface's prefixes (Prefix Information)

  An interface that sends Router Advertisements (`ipv6
  router-advertisements send-advertisements true`) names in them the /64
  of each of its global addresses, so that the hosts on it form their
  own addresses (RFC 4861 §6.2.1, RFC 4862). That is what gets the hosts
  behind a router an address from the prefix it was delegated (RFC 7084
  L-2): `dhcpv6-options pd <id> interface <lan>` puts an address of the
  prefix on the interface, and the advertisement names its /64.

  - A prefix whose address never ends is advertised with RFC 4861's
    lifetimes; one whose address has lifetimes (the lease's) with what
    is left of them.
  - A renewal is told soon, not with the next periodic advertisement,
    also when it gives the same lifetimes as the one before.
  - A prefix that goes is advertised with both lifetimes zero (RFC 9096
    §3.5): the hosts stop using their address in it for new connections
    and no longer take it for on-link. It is named that way until the
    longest valid lifetime it was ever advertised with is over.

  Topology: s1 is the ISP side, a router with the small DHCPv6 server of
  dhcpv6_client_pd.feature, which routes what it delegates, and the
  prefix lan0 is numbered with by hand, to the client. r1 is zebra-rs:
  a DHCPv6 WAN, and lan0 behind it, which advertises. h1 is a host on
  lan0 with nothing configured: its kernel forms its addresses and its
  default route from what r1 advertises.

      s1 (dhcpv6_server.py) srv0 fe80::1 ──── wan0 r1 lan0 ──── eth0 h1
         lo 2001:db8:ffff::1/128             (pd 1)  2001:db8:aa::1/64
         pd 1 = 2001:db8:100::/56, later 2001:db8:900::/56

  Requires python3 on the host.

  Config files:
  - r1.yaml: `address dhcpv6` and `pd 1 length 56 interface lan0 sla-id 1 address 1` on wan0; `2001:db8:aa::1/64` and `router-advertisements send-advertisements true` on lan0.

  Scenario: Setup the delegating router, the advertising router and a host
    Given a clean test environment
    When I create namespace "s1"
    And I create namespace "r1"
    And I create namespace "h1"
    And I connect namespace "s1" interface "srv0" to namespace "r1" interface "wan0"
    And I connect namespace "r1" interface "lan0" to namespace "h1" interface "eth0"
    And I execute "sysctl -q -w net.ipv6.conf.all.forwarding=1" in namespace "r1"
    And I execute "ip addr add fe80::1/64 dev srv0 nodad" in namespace "s1"
    And I execute "ip link set lo up" in namespace "s1"
    And I execute "ip -6 addr add 2001:db8:ffff::1/128 dev lo" in namespace "s1"
    And I execute "sysctl -q -w net.ipv6.conf.all.forwarding=1" in namespace "s1"
    And I execute "tests/scripts/dhcpv6_server.py ra_prefix start srv0 --address 2001:db8:1::100 --pd 1=2001:db8:100::/56 --route --route-also 2001:db8:aa::/64" in namespace "s1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "on lan0:    2001:db8:100:1::1/64"
    When I execute "tests/scripts/ra_sender.py srv0 --source fe80::1" in namespace "s1"
    Then show command "show ipv6 route" in namespace "r1" should eventually contain "::/0 [210/0] via fe80::1"

  Scenario: The advertisements name both prefixes of the interface
    Given the test topology exists
    # The configured address's, with RFC 4861's 30 and 7 days, and the
    # delegated prefix's, with what is left of the lease's two hours and
    # one.
    Then show command "show ipv6 nd interface lan0" in namespace "r1" should eventually contain "Prefixes (2):"
    And show command "show ipv6 nd interface lan0" in namespace "r1" should eventually contain "2001:db8:aa::/64 valid 720h, preferred 168h"
    And show command "show ipv6 nd interface lan0" in namespace "r1" should eventually contain "2001:db8:100:1::/64 valid 1h5"
    # The WAN interface advertises nothing: it is not told to.
    And show command "show ipv6 nd interface wan0" in namespace "r1" should contain "Router advertisement: disabled"

  Scenario: A host with nothing configured gets its addresses and its route
    Given the test topology exists
    # The kernel of h1 forms an address in each advertised /64, and takes
    # r1 for its default router.
    Then command "ip -6 addr show dev eth0 scope global" in namespace "h1" should eventually contain "inet6 2001:db8:100:1:"
    And command "ip -6 addr show dev eth0 scope global" in namespace "h1" should eventually contain "inet6 2001:db8:aa:"
    And command "ip -6 route show default" in namespace "h1" should eventually contain "default via fe80::"
    And command "ip -6 route show 2001:db8:100:1::/64" in namespace "h1" should eventually contain "dev eth0 proto kernel"
    # The configured prefix's 30 days, counting down.
    And command "ip -6 addr show dev eth0 scope global" in namespace "h1" should eventually contain "valid_lft 2591"
    # From the host out through the delegating router and back.
    And command "tests/scripts/ping6_once.sh 2001:db8:ffff::1" in namespace "h1" should eventually contain "1 received"

  Scenario: A renewal is told to the hosts soon
    Given the test topology exists
    # The advertisements that follow a new prefix are over: the next one
    # is the periodic one, minutes away.
    Then show command "show ipv6 nd interface lan0" in namespace "r1" should eventually contain "initial advertisements remaining 0"
    # The server comes back with longer lifetimes. The lease's new times
    # are the address's on lan0, and an advertisement that does not
    # wait for its period has the host's address follow.
    When I execute "tests/scripts/dhcpv6_server.py ra_prefix stop" in namespace "s1"
    And I execute "tests/scripts/dhcpv6_server.py ra_prefix start srv0 --address 2001:db8:1::100 --pd 1=2001:db8:100::/56 --route --route-also 2001:db8:aa::/64 --preferred 30000 --valid 60000" in namespace "s1"
    Then show command "renew dhcpv6 interface wan0" in namespace "r1" should contain "Renewing the DHCPv6 lease on wan0"
    And show command "show ipv6 nd interface lan0" in namespace "r1" should eventually contain "2001:db8:100:1::/64 valid 16h3"
    And command "ip -6 addr show dev eth0 scope global" in namespace "h1" should eventually contain "valid_lft 59"

  Scenario: A renewal with the same lifetimes still moves their end
    Given the test topology exists
    # The server now gives 200 s, and gives them again with every
    # renewal: the numbers do not change, and the prefix lasts longer
    # all the same.
    When I execute "tests/scripts/dhcpv6_server.py ra_prefix stop" in namespace "s1"
    And I execute "tests/scripts/dhcpv6_server.py ra_prefix start srv0 --address 2001:db8:1::100 --pd 1=2001:db8:100::/56 --route --route-also 2001:db8:aa::/64 --preferred 100 --valid 200" in namespace "s1"
    Then show command "renew dhcpv6 interface wan0" in namespace "r1" should contain "Renewing the DHCPv6 lease on wan0"
    And show command "show ipv6 nd interface lan0" in namespace "r1" should eventually contain "2001:db8:100:1::/64 valid 3m1"
    # Twenty seconds on, less than three minutes are left of it.
    And show command "show ipv6 nd interface lan0" in namespace "r1" should eventually contain "2001:db8:100:1::/64 valid 2m5"
    # Renewed, with the 200 s it had before: over three minutes again.
    And show command "renew dhcpv6 interface wan0" in namespace "r1" should contain "Renewing the DHCPv6 lease on wan0"
    And show command "show ipv6 nd interface lan0" in namespace "r1" should eventually contain "2001:db8:100:1::/64 valid 3m1"

  Scenario: A prefix that is replaced is taken out of use on the hosts
    Given the test topology exists
    When I execute "tests/scripts/dhcpv6_server.py ra_prefix stop" in namespace "s1"
    And I execute "tests/scripts/dhcpv6_server.py ra_prefix start srv0 --address 2001:db8:1::100 --pd 1=2001:db8:900::/56 --route --route-also 2001:db8:aa::/64 --preferred 30000 --valid 60000" in namespace "s1"
    Then show command "renew dhcpv6 interface wan0" in namespace "r1" should contain "Renewing the DHCPv6 lease on wan0"
    And show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "on lan0:    2001:db8:900:1::1/64"
    # The new prefix is advertised, and the old one with both lifetimes
    # zero, until the 60000 s it was once advertised with are over,
    # though its lease was cut to 200 s since: a host may have heard
    # the longer lifetime only.
    And show command "show ipv6 nd interface lan0" in namespace "r1" should eventually contain "2001:db8:900:1::/64 valid 16h3"
    And show command "show ipv6 nd interface lan0" in namespace "r1" should eventually contain "2001:db8:100:1::/64 valid 0s, preferred 0s (withdrawn, named for another 16h3"
    # The host has an address of the new prefix, no longer starts a
    # connection from the old one, and no longer takes the old prefix
    # for on-link.
    And command "ip -6 addr show dev eth0 scope global" in namespace "h1" should eventually contain "inet6 2001:db8:900:1:"
    And command "ip -6 addr show dev eth0 deprecated" in namespace "h1" should eventually contain "inet6 2001:db8:100:1:"
    And command "ip -6 addr show dev eth0 deprecated" in namespace "h1" should not contain "inet6 2001:db8:900:1:"
    And command "ip -6 route show 2001:db8:100:1::/64" in namespace "h1" should eventually not contain "dev eth0"
    And command "ip -6 route show 2001:db8:900:1::/64" in namespace "h1" should eventually contain "dev eth0 proto kernel"
    And command "tests/scripts/ping6_once.sh 2001:db8:ffff::1" in namespace "h1" should eventually contain "1 received"

  Scenario: A configured address that is deleted takes its prefix out of use too
    Given the test topology exists
    When I apply command "delete interface lan0 ipv6 address 2001:db8:aa::1/64" in namespace "r1"
    # Its 30 days are how long it is still named.
    Then show command "show ipv6 nd interface lan0" in namespace "r1" should eventually contain "2001:db8:aa::/64 valid 0s, preferred 0s (withdrawn, named for another 719h"
    And command "ip -6 addr show dev eth0 deprecated" in namespace "h1" should eventually contain "inet6 2001:db8:aa:"
    # Configured again, it is advertised as before, and the host's
    # address is preferred again.
    When I apply command "set interface lan0 ipv6 address 2001:db8:aa::1/64" in namespace "r1"
    Then show command "show ipv6 nd interface lan0" in namespace "r1" should eventually contain "2001:db8:aa::/64 valid 720h, preferred 168h"
    And command "ip -6 addr show dev eth0 deprecated" in namespace "h1" should eventually not contain "inet6 2001:db8:aa:"

  Scenario: A delegation that is given back takes its prefix out of use
    Given the test topology exists
    When I apply command "delete interface wan0 ipv6 dhcpv6-options pd 1" in namespace "r1"
    Then command "cat /tmp/zebra-bdd-dhcp/ra_prefix/server.log" in namespace "s1" should eventually contain "RELEASE ia_na"
    And show command "show ipv6 nd interface lan0" in namespace "r1" should eventually contain "2001:db8:900:1::/64 valid 0s, preferred 0s (withdrawn"
    And command "ip -6 addr show dev eth0 deprecated" in namespace "h1" should eventually contain "inet6 2001:db8:900:1:"

  Scenario: An interface that stops advertising names nothing
    Given the test topology exists
    When I apply command "delete interface lan0 ipv6 router-advertisements send-advertisements" in namespace "r1"
    Then show command "show ipv6 nd interface lan0" in namespace "r1" should eventually contain "Router advertisement: disabled"
    And show command "show ipv6 nd interface lan0" in namespace "r1" should not contain "Prefixes ("
    # No lease is left for a later run of this feature to resume.
    When I apply command "delete interface wan0 ipv6 address dhcpv6" in namespace "r1"
    Then show command "show dhcpv6 client leases" in namespace "r1" should eventually contain "DHCPv6 client is not configured"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcpv6_server.py ra_prefix stop" in namespace "s1"
    And I delete namespace "h1"
    And I delete namespace "r1"
    And I delete namespace "s1"
    Then the test environment should be clean
