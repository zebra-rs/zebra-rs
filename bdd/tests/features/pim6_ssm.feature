@serial
@pim6_ssm
Feature: PIMv6 SSM (S,G) forwarding end to end across two routers
  As a network operator
  I want an MLDv2 source-specific join at the last-hop router to build
  an IPv6 (S,G) shortest-path tree back to the first-hop router and
  program the kernel MRT6 forwarding cache on both, so real IPv6 traffic
  from the source reaches the receiver — the first complete PIMv6
  control-plane-to-dataplane slice (MLD + PIMv6 J/P + the MRT6/MIF/MFC
  datapath).

  h1 sends UDPv6 to the SSM group ff3e::1. h2 issues a source-specific
  join for (2001:db8:14::2, ff3e::1). r2 (LHR) must translate the MLDv2
  membership into a PIMv6 (S,G) Join toward r1 — its RPF nexthop is r1's
  global on the transit link (a static route), which r1 advertises as a
  Hello secondary address so r2's neighbor_covers() matches it; the Join
  itself is sourced from r2's link-local. r1 (FHR, source directly
  connected) accepts the Join into its downstream state, and both
  install kernel MRT6 MFC entries that forward h1's datagrams to h2.

  Test Topology:
  ```
    h1 (2001:db8:14::2, sender) --- eth4/eth3 --- r1 --- eth1/eth2 --- r2 --- eth5/eth6 --- h2 (2001:db8:15::2, receiver)
                                       2001:db8:14::1   2001:db8:13::1/.2       2001:db8:15::1
  ```

  Scenario: SSM join builds the IPv6 (S,G) tree and traffic flows
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "h1"
    And I create namespace "h2"
    And I connect namespace "r1" interface "eth1" to namespace "r2" interface "eth2"
    And I connect namespace "r1" interface "eth3" to namespace "h1" interface "eth4"
    And I connect namespace "r2" interface "eth5" to namespace "h2" interface "eth6"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I add address "2001:db8:14::2/64" to interface "eth4" in namespace "h1"
    And I add address "2001:db8:15::2/64" to interface "eth6" in namespace "h2"

    # Both transit interfaces run PIMv6 and form a link-local neighborship.
    Then show command "show pim ipv6 interface" in namespace "r1" should eventually contain "Up"
    And show command "show pim ipv6 interface" in namespace "r2" should eventually contain "Up"
    And show command "show pim ipv6 neighbor" in namespace "r2" should eventually contain "fe80"

    # h2 source-specifically joins (2001:db8:14::2, ff3e::1): r2 turns the
    # MLDv2 membership into an (S,G) Join toward r1.
    When I spawn "timeout 150 python3 tests/scripts/ssm_recv6.py ff3e::1 2001:db8:14::2 eth6 5001 /tmp/pim6_ssm_rx" in namespace "h2"
    Then show command "show pim ipv6 mld groups" in namespace "r2" should eventually contain "ff3e::1"

    # Kernel MRT6 MFC on both routers, with the expected IIF/OIF split.
    # r1 learned the (S,G) from r2's PIMv6 Join — no MLD on that path.
    And command "ip -6 mroute show" in namespace "r1" should eventually contain "Iif: eth3"
    And command "ip -6 mroute show" in namespace "r1" should eventually contain "eth1"
    And command "ip -6 mroute show" in namespace "r2" should eventually contain "Iif: eth2"
    And command "ip -6 mroute show" in namespace "r2" should eventually contain "eth5"

    # The datapath proof: h1's IPv6 datagrams arrive at h2's receiver.
    When I spawn "timeout 120 python3 tests/scripts/mcast_send6.py ff3e::1 5001 eth4 90" in namespace "h1"
    Then command "cat /tmp/pim6_ssm_rx" in namespace "h2" should eventually contain "ssm-hello"

  Scenario: Teardown topology
    When I execute "rm -f /tmp/pim6_ssm_rx" in namespace "h2"
    And I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "h1"
    And I delete namespace "h2"
    Then the test environment should be clean
