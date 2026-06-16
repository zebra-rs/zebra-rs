@serial
@bgp_neighbor_adj_rib_v6
Feature: show bgp neighbors <X> advertised-routes / received-routes ipv6
  As a network operator
  I want to inspect a single neighbor's IPv6-unicast Adj-RIB-Out and
  Adj-RIB-In, so I can see exactly what was advertised to, and received
  from, that peer for the v6 address family.

  These are the v6-unicast twins of the existing (bare) v4 forms:
  `advertised-routes ipv6` reads the peer's `adj_out.v6`, and
  `received-routes ipv6` reads its `adj_in.v6`. The IPv6 Adj-RIB-Out
  always lives on the peer (the per-peer egress task is v4-only) and the
  IPv6 Adj-RIB-In lives in main's shard (v6 ingest never moves to the
  pool), so both reads are correct at any shard count.

  Topology: one dual-stack point-to-point link, eBGP over the IPv4
  transport with both ipv4 and ipv6 afi-safi negotiated, both sides
  redistributing connected. The session is keyed by the IPv4 transport
  address; the `ipv6` keyword selects the v6 Adj-RIB on that peer.

  Scenario: A neighbor's v6 Adj-RIB-Out and Adj-RIB-In are visible per peer
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 10 seconds
    Then show command "show bgp summary" in namespace "z1" should contain "Established"
    # Sanity: the v6 routes converged across the session.
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8::1/128"
    # Adj-RIB-Out, z1 -> z2 (the IPv4-transport peer): z1's own loopback
    # was advertised to z2 over the v6 AFI.
    And show command "show bgp neighbors 192.168.0.2 advertised-routes ipv6" in namespace "z1" should contain "2001:db8::1/128"
    # The Adj-RIB-Out is per-peer, not a whole-table dump: z2's own
    # loopback (learned FROM z2) is never advertised back to z2. The
    # positive assertion above on the same command guards this negative
    # from passing vacuously (an unparsed command returns empty output).
    And show command "show bgp neighbors 192.168.0.2 advertised-routes ipv6" in namespace "z1" should not contain "2001:db8::2/128"
    # Adj-RIB-In, z2 <- z1: z2 received z1's loopback and the shared link
    # prefix from neighbor 192.168.0.1. Both present => the v6 Adj-RIB-In
    # read is complete, and the negative below is non-vacuous.
    And show command "show bgp neighbors 192.168.0.1 received-routes ipv6" in namespace "z2" should contain "2001:db8::1/128"
    And show command "show bgp neighbors 192.168.0.1 received-routes ipv6" in namespace "z2" should contain "2001:db8:12::/64"

  Scenario: A post-establishment v6 prefix appears, then withdraws, from the Adj-RIBs
    Given the test topology exists
    # Inject a fresh connected v6 prefix on z1 with the session already
    # up, so it can only reach z2 through the incremental advertise path.
    When I create dummy interface "cust0" with address "2001:db8:cafe::1/64" in namespace "z1"
    And I wait 8 seconds
    # It is recorded in z1's v6 Adj-RIB-Out toward z2 and z2's v6
    # Adj-RIB-In from z1.
    Then show command "show bgp neighbors 192.168.0.2 advertised-routes ipv6" in namespace "z1" should contain "2001:db8:cafe::/64"
    And show command "show bgp neighbors 192.168.0.1 received-routes ipv6" in namespace "z2" should contain "2001:db8:cafe::/64"
    # Downing the dummy flushes its v6 address (kernel semantics), so z1
    # withdraws the origination. The MP_UNREACH must clear it from both
    # Adj-RIBs. The link prefix stays as the positive control so neither
    # negative assertion passes vacuously.
    When I make namespace "z1" interface "cust0" down
    And I wait 8 seconds
    Then show command "show bgp neighbors 192.168.0.2 advertised-routes ipv6" in namespace "z1" should not contain "2001:db8:cafe::/64"
    And show command "show bgp neighbors 192.168.0.2 advertised-routes ipv6" in namespace "z1" should contain "2001:db8:12::/64"
    And show command "show bgp neighbors 192.168.0.1 received-routes ipv6" in namespace "z2" should not contain "2001:db8:cafe::/64"
    And show command "show bgp neighbors 192.168.0.1 received-routes ipv6" in namespace "z2" should contain "2001:db8:12::/64"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
