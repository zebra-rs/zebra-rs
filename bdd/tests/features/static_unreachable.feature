@serial
@static_unreachable
Feature: Static unreachable routes (router static ... nexthop unreachable)

  `router static ipv4|ipv6 route <prefix> nexthop unreachable` is a
  discard route that tells the sender: a packet for the prefix is
  dropped here and answered with an ICMP Destination Unreachable
  (kernel RTN_UNREACHABLE), so whoever sent it fails at once.
  `nexthop blackhole` drops it without a word
  (static_blackhole.feature), and the sender waits. A route takes one
  of the two keywords.

  Topology: h is a plain host behind r, which is zebra-rs and forwards.

      h eth0 192.0.2.2, 2001:db8:1::2 ---- lan0 192.0.2.1, 2001:db8:1::1 r

  Config files:
  - r.yaml: 10.9.9.0/24 and 2001:db8:dead::/48 unreachable, 10.8.8.0/24 and 2001:db8:beef::/48 blackhole, and 10.9.9.0/24 unreachable in VRF blue.
  - r_swapped.yaml: the same with the two keywords the other way round.
  - r_none.yaml: no static route.

  Scenario: Setup a router with discard routes of both kinds and a host behind it
    Given a clean test environment
    When I create namespace "r"
    And I create namespace "h"
    And I connect namespace "r" interface "lan0" to namespace "h" interface "eth0"
    And I execute "sysctl -q -w net.ipv4.ip_forward=1" in namespace "r"
    And I execute "sysctl -q -w net.ipv6.conf.all.forwarding=1" in namespace "r"
    And I execute "ip addr add 192.0.2.2/24 dev eth0" in namespace "h"
    And I execute "ip -6 addr add 2001:db8:1::2/64 dev eth0 nodad" in namespace "h"
    And I execute "ip route add default via 192.0.2.1" in namespace "h"
    And I execute "ip -6 route add default via 2001:db8:1::1" in namespace "h"
    And I start zebra-rs in namespace "r"
    And I apply config "r.yaml" to namespace "r"
    Then ping from "h" to "192.0.2.1" should eventually succeed
    And command "tests/scripts/ping_once.sh 2001:db8:1::1" in namespace "h" should eventually contain "1 received"

  Scenario: The routes are unreachable routes in the RIB and in the kernel
    Given the test topology exists
    Then kernel route "10.9.9.0/24" in namespace "r" should eventually contain "unreachable 10.9.9.0/24 proto zebra"
    And kernel route "2001:db8:dead::/48" in namespace "r" should eventually contain "unreachable 2001:db8:dead::/48"
    And kernel route "2001:db8:dead::/48" in namespace "r" should eventually contain "proto zebra"
    And show command "show ip route" in namespace "r" should eventually contain "S  *> 10.9.9.0/24 [1/0] is a discard (unreachable)"
    And show command "show ipv6 route" in namespace "r" should eventually contain "S  *> 2001:db8:dead::/48 [1/0] is a discard (unreachable)"
    And show command "show ip route 10.9.9.0/24" in namespace "r" should eventually contain "discard (unreachable)"
    # The blackhole routes beside them are what they were.
    And kernel route "10.8.8.0/24" in namespace "r" should eventually contain "blackhole 10.8.8.0/24 proto zebra"
    And show command "show ip route" in namespace "r" should eventually contain "S  *> 10.8.8.0/24 [1/0] is a discard (blackhole)"
    # A VRF's static routes take the keyword too.
    And command "ip route show vrf blue 10.9.9.0/24" in namespace "r" should eventually contain "unreachable 10.9.9.0/24 proto zebra"

  Scenario: The sender of a packet for an unreachable route is told, and for a blackhole route is not
    Given the test topology exists
    Then command "tests/scripts/ping_once.sh 10.9.9.1" in namespace "h" should eventually contain "From 192.0.2.1 icmp_seq=1 Destination Host Unreachable"
    And command "tests/scripts/ping_once.sh 2001:db8:dead::1" in namespace "h" should eventually contain "From 2001:db8:1::1 icmp_seq=1 Destination unreachable: No route"
    # The blackhole routes are there (the scenario above), and say
    # nothing: the echo request is lost and that is all the host sees.
    And command "tests/scripts/ping_once.sh 10.8.8.1" in namespace "h" should eventually contain "0 received"
    And command "tests/scripts/ping_once.sh 10.8.8.1" in namespace "h" should not contain "nreachable"
    And command "tests/scripts/ping_once.sh 2001:db8:beef::1" in namespace "h" should eventually contain "0 received"
    And command "tests/scripts/ping_once.sh 2001:db8:beef::1" in namespace "h" should not contain "nreachable"

  Scenario: One keyword takes the other's place in one commit
    Given the test topology exists
    When I apply config "r_swapped.yaml" to namespace "r"
    Then kernel route "10.9.9.0/24" in namespace "r" should eventually contain "blackhole 10.9.9.0/24 proto zebra"
    And kernel route "10.8.8.0/24" in namespace "r" should eventually contain "unreachable 10.8.8.0/24 proto zebra"
    And kernel route "2001:db8:dead::/48" in namespace "r" should eventually contain "blackhole 2001:db8:dead::/48"
    And kernel route "2001:db8:beef::/48" in namespace "r" should eventually contain "unreachable 2001:db8:beef::/48"
    And command "ip route show vrf blue 10.9.9.0/24" in namespace "r" should eventually contain "blackhole 10.9.9.0/24 proto zebra"
    And show command "show ip route" in namespace "r" should eventually contain "10.9.9.0/24 [1/0] is a discard (blackhole)"
    And show command "show ip route" in namespace "r" should eventually contain "10.8.8.0/24 [1/0] is a discard (unreachable)"
    # And what the host hears has changed sides with them.
    And command "tests/scripts/ping_once.sh 10.8.8.1" in namespace "h" should eventually contain "From 192.0.2.1 icmp_seq=1 Destination Host Unreachable"
    And command "tests/scripts/ping_once.sh 2001:db8:beef::1" in namespace "h" should eventually contain "From 2001:db8:1::1 icmp_seq=1 Destination unreachable: No route"
    And command "tests/scripts/ping_once.sh 10.9.9.1" in namespace "h" should eventually contain "0 received"
    And command "tests/scripts/ping_once.sh 10.9.9.1" in namespace "h" should not contain "nreachable"
    When I apply config "r.yaml" to namespace "r"
    Then kernel route "10.9.9.0/24" in namespace "r" should eventually contain "unreachable 10.9.9.0/24 proto zebra"
    And kernel route "10.8.8.0/24" in namespace "r" should eventually contain "blackhole 10.8.8.0/24 proto zebra"
    And kernel route "2001:db8:dead::/48" in namespace "r" should eventually contain "unreachable 2001:db8:dead::/48"

  Scenario: Both keywords on one route are refused
    Given the test topology exists
    Then applying command "set router static ipv4 route 10.9.9.0/24 nexthop blackhole" in namespace "r" should be rejected with "nexthop blackhole cannot be combined with nexthop unreachable"
    And applying command "set router static ipv6 route 2001:db8:beef::/48 nexthop unreachable" in namespace "r" should be rejected with "nexthop blackhole cannot be combined with nexthop unreachable"
    And applying command "set router static vrf blue ipv4 route 10.9.9.0/24 nexthop blackhole" in namespace "r" should be rejected with "router static vrf blue ipv4 route 10.9.9.0/24"
    # Nothing of the refused commits was applied.
    And kernel route "10.9.9.0/24" in namespace "r" should eventually contain "unreachable 10.9.9.0/24 proto zebra"
    And kernel route "2001:db8:beef::/48" in namespace "r" should eventually contain "blackhole 2001:db8:beef::/48"

  Scenario: A restart keeps the unreachable routes
    Given the test topology exists
    # The routes outlive the daemon in the kernel, and the configuration
    # that still has them takes them over.
    When I stop zebra-rs in namespace "r"
    Then kernel route "10.9.9.0/24" in namespace "r" should eventually contain "unreachable 10.9.9.0/24 proto zebra"
    When I start zebra-rs in namespace "r" sweeping leftovers after 15 seconds
    And I apply config "r.yaml" to namespace "r"
    Then show command "show ip route" in namespace "r" should eventually contain "S  *> 10.9.9.0/24 [1/0] is a discard (unreachable)"
    And I wait 20 seconds
    # Past the sweep, they are still there: they are this run's now.
    And kernel route "10.9.9.0/24" in namespace "r" should eventually contain "unreachable 10.9.9.0/24 proto zebra"
    And kernel route "2001:db8:dead::/48" in namespace "r" should eventually contain "unreachable 2001:db8:dead::/48"
    And command "tests/scripts/ping_once.sh 10.9.9.1" in namespace "h" should eventually contain "From 192.0.2.1 icmp_seq=1 Destination Host Unreachable"

  Scenario: A restart without the routes takes the earlier run's away
    Given the test topology exists
    # Started again with a configuration that has them no longer, they
    # are an earlier run's leftovers: the leftover sweep takes them, of
    # either kind and either family.
    When I stop zebra-rs in namespace "r"
    Then kernel route "2001:db8:dead::/48" in namespace "r" should eventually contain "unreachable 2001:db8:dead::/48"
    When I start zebra-rs in namespace "r" sweeping leftovers after 15 seconds
    And I apply config "r_none.yaml" to namespace "r"
    Then kernel route "10.9.9.0/24" in namespace "r" should eventually be gone
    And kernel route "2001:db8:dead::/48" in namespace "r" should eventually be gone
    And kernel route "10.8.8.0/24" in namespace "r" should eventually be gone
    And kernel route "2001:db8:beef::/48" in namespace "r" should eventually be gone
    And show command "show ip route" in namespace "r" should eventually not contain "10.9.9.0/24"

  Scenario: A deleted route is withdrawn
    Given the test topology exists
    When I apply config "r.yaml" to namespace "r"
    Then kernel route "10.9.9.0/24" in namespace "r" should eventually contain "unreachable 10.9.9.0/24 proto zebra"
    When I apply command "delete router static ipv4 route 10.9.9.0/24 nexthop unreachable" in namespace "r"
    And I apply command "delete router static ipv6 route 2001:db8:dead::/48" in namespace "r"
    Then kernel route "10.9.9.0/24" in namespace "r" should eventually be gone
    And kernel route "2001:db8:dead::/48" in namespace "r" should eventually be gone
    And show command "show ip route" in namespace "r" should eventually not contain "10.9.9.0/24 [1/0]"
    # The routes beside them stay.
    And kernel route "10.8.8.0/24" in namespace "r" should eventually contain "blackhole 10.8.8.0/24 proto zebra"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r"
    And I delete namespace "r"
    And I delete namespace "h"
    Then the test environment should be clean
