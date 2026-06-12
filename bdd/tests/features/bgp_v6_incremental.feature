@serial
@bgp_v6_incremental
Feature: IPv6 unicast routes appearing after session establishment are advertised
  As a network operator
  I want an IPv6 route that shows up while a BGP session is already
  Established to be advertised to that peer, so convergence does not
  depend on session resets.

  Regression guard: the incremental v6 advertise path
  (`route_advertise_to_peers_v6`) emits reach only through the
  per-update-group `cache_ipv6`, but `(Ip6, Unicast)` was never in
  `TRACKED_AFI_SAFIS`, so `update_group::attach` never enrolled any
  peer and the group lookup always missed — incremental v6 reach was
  silently dropped. Only the initial `route_sync_ipv6` dump at
  establishment delivered v6 routes, which is why every pre-existing
  feature (config applied before the session comes up) kept passing.

  Topology: one dual-stack point-to-point link, eBGP over the IPv4
  addresses with both ipv4 and ipv6 afi-safi negotiated, both sides
  redistributing connected. adv-interval is pinned to 1s. The route
  under test is injected via a dummy interface created only AFTER the
  session is verified Established, so it can only reach the peer
  through the incremental path.

  Scenario: A connected v6 prefix added after Established reaches the peer
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
    # Baseline: initial-sync routes made it across (this path always
    # worked — it is not the subject of the test).
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8::1/128"
    # Inject a new connected prefix only now, with the session up.
    When I create dummy interface "cust0" with address "2001:db8:cafe::1/64" in namespace "z1"
    And I wait 8 seconds
    # Origination on z1 (kernel AddrAdd -> redistribute connected).
    Then show command "show bgp ipv6" in namespace "z1" should contain "2001:db8:cafe::/64"
    # The incremental advertisement must arrive at z2: bucketed into
    # the v6 update-group cache and debounce-flushed. Before the fix
    # the group gate always missed and this prefix never arrived.
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:cafe::/64"
    And show command "show ipv6 route" in namespace "z2" should contain "2001:db8:cafe::/64"

  Scenario: Withdrawing the prefix after Established removes it from the peer
    Given the test topology exists
    # Downing the dummy flushes its v6 address (kernel semantics for
    # IPv6), so z1 sees AddrDel, the origination is withdrawn, and the
    # incremental MP_UNREACH must clear the route on z2.
    When I make namespace "z1" interface "cust0" down
    And I wait 8 seconds
    Then show command "show bgp ipv6" in namespace "z2" should not contain "2001:db8:cafe::/64"
    # Guard against a vacuous pass of the negative assertion above: the
    # same table must still carry the unrelated link prefix.
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:12::/64"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
