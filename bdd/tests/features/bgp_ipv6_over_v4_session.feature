@serial
@bgp_ipv6_over_v4_session
Feature: IPv6 NLRI over a v4-addressed BGP session carries a usable next-hop
  As a network operator
  I want IPv6 routes advertised across an IPv4-addressed BGP session to
  carry a real IPv6 next-hop (RFC 2545 §2), so the receiver can resolve,
  install and forward them — not just display them.

  Regression guard: next-hop-self only fired when the session's local
  end was itself IPv6, so v6 NLRI over v4 transport went out with `::`
  as the MP_REACH next-hop. The receiver kept those routes best-path
  selected but could never install them. The fix sources the next-hop
  from the session interface's global IPv6 (the v4 local end's owning
  interface), and skips the advertisement entirely when no usable v6
  next-hop exists rather than emitting `::`.

  Topology: one dual-stack point-to-point link, eBGP over the IPv4
  addresses with both ipv4 and ipv6 afi-safi negotiated, both sides
  redistributing connected (loopbacks 10.0.0.X/32 + 2001:db8::X/128,
  link 192.168.0.0/30 + 2001:db8:12::/64).

  Scenario: v6 routes arrive with the peer's interface global as next-hop
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 10 seconds
    # "eventually": 10s is a margin, not a guarantee, when the host is
    # running other features concurrently.
    Then show command "show bgp summary" in namespace "z1" should eventually contain "Established"
    # z2's loopback arrived over the v6 AFI with z2's interface global
    # (2001:db8:12::2) as the next-hop — not `::`.
    And show command "show bgp ipv6" in namespace "z1" should eventually contain "2001:db8::2/128"
    And show command "show bgp ipv6" in namespace "z1" should contain "2001:db8:12::2"
    # Symmetric on z2.
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8::1/128"
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:12::1"

  Scenario: The v6 routes resolve, install into the RIB and forward
    Given the test topology exists
    # A resolvable next-hop means the route makes it past best-path
    # into the main v6 RIB (it never did while the next-hop was `::`)...
    Then show command "show ipv6 route" in namespace "z1" should eventually contain "2001:db8::2/128"
    And show command "show ipv6 route" in namespace "z2" should contain "2001:db8::1/128"
    # ...and the dataplane forwards loopback-to-loopback both ways.
    And ping from "z1" to "2001:db8::2" should succeed
    And ping from "z2" to "2001:db8::1" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
