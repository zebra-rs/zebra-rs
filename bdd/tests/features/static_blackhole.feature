@serial
@static_blackhole
Feature: Static blackhole routes install RTN_BLACKHOLE discard entries
  As a network operator
  I want `router static <afi> route <prefix> nexthop blackhole` to
  install a discard route in the forwarding plane (kernel
  RTN_BLACKHOLE) with no gateway — so that traffic to the prefix is
  dropped at this router instead of forwarded or looped. This
  exercises the RIB `Nexthop::Blackhole` type end to end (config →
  RIB → netlink → kernel FIB).

  Scenario: IPv4 and IPv6 blackhole static routes reach the kernel FIB
    Given a clean test environment
    When I create namespace "r"
    And I start zebra-rs in namespace "r"
    And I apply config "r.yaml" to namespace "r"
    And I wait 5 seconds

    # The kernel FIB renders a discard route as `blackhole <prefix>`
    # with no `via`/`dev` gateway.
    Then kernel route "10.9.9.0/24" in namespace "r" should eventually contain "blackhole"
    And kernel route "2001:db8:dead::/48" in namespace "r" should eventually contain "blackhole"

    # Removing the route withdraws the discard entry.
    When I apply command "delete router static ipv4 route 10.9.9.0/24 nexthop blackhole" in namespace "r"
    Then kernel route "10.9.9.0/24" in namespace "r" should eventually be gone

    # Teardown.
    When I stop zebra-rs in namespace "r"
    And I delete namespace "r"
    Then the test environment should be clean
