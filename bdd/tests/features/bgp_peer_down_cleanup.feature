@serial
@bgp_peer_down_cleanup
Feature: BGP session loss withdraws every AFI/SAFI the peer contributed
  As a network operator
  I want a BGP session that leaves Established to take all of that
  neighbour's routes with it — across every negotiated AFI/SAFI — so
  that traffic never follows a route whose only source is a dead peer.

  Regression guard: `route_clean` (the leaving-Established hook) used
  to cover IPv4 unicast, VPNv4, EVPN and labeled-unicast but skipped
  IPv6 unicast entirely — a session drop left the peer's IPv6 routes
  best-path-selected forever, while the same peer's IPv4 routes were
  correctly withdrawn. The fix also swept the same gap for VPNv6,
  Flowspec, BGP-LS and SR Policy; this feature pins the dual-stack
  unicast behaviour end to end.

  Topology: one dual-stack point-to-point link, eBGP over the IPv4
  addresses with both ipv4 and ipv6 afi-safi negotiated, both sides
  redistributing connected (loopbacks 10.0.0.X/32 + 2001:db8::X/128).

  Scenario: Establish the dual-stack session and learn both AFIs
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
    # z2's loopbacks arrived over both AFIs.
    And show command "show bgp" in namespace "z1" should contain "10.0.0.2/32"
    And show command "show bgp ipv6" in namespace "z1" should contain "2001:db8::2/128"
    # And the IPv4 route made it into the main RIB.
    And show command "show ip route" in namespace "z1" should contain "10.0.0.2/32"

  Scenario: Killing the peer withdraws IPv4 AND IPv6 routes
    Given the test topology exists
    When I stop zebra-rs in namespace "z2"
    And I wait 5 seconds
    # The session left Established...
    Then show command "show bgp summary" in namespace "z1" should not contain "Established"
    # ...and BOTH address families are gone. The IPv6 assertion is the
    # regression: it used to stay best-path-selected forever.
    And show command "show bgp" in namespace "z1" should not contain "10.0.0.2/32"
    And show command "show bgp ipv6" in namespace "z1" should not contain "2001:db8::2/128"
    And show command "show ip route" in namespace "z1" should not contain "10.0.0.2/32"

  Scenario: The session re-establishes and both AFIs are re-learned
    Given the test topology exists
    When I start zebra-rs in namespace "z2"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 15 seconds
    Then show command "show bgp summary" in namespace "z1" should contain "Established"
    # Both directions re-learn both AFIs — z1's adj-out was cleared on
    # the drop, so z2 receives a full re-advertisement too.
    And show command "show bgp" in namespace "z1" should contain "10.0.0.2/32"
    And show command "show bgp ipv6" in namespace "z1" should contain "2001:db8::2/128"
    And show command "show bgp" in namespace "z2" should contain "10.0.0.1/32"
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8::1/128"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
