@serial
@bgp_v6_route_map
Feature: BGP per-peer route-map for IPv6 unicast (inbound + outbound)
  As a network operator
  I want `neighbor X afi-safi ipv6 policy in/out <policy>` to filter and
  rewrite IPv6 unicast routes per neighbor — the same per-peer per-family
  route-map semantics
  the IPv4 unicast path already has. Before this, the v6 ingest and the
  v6 advertise applied no per-neighbor policy, so v6 route-maps were
  silently ignored (the global `table-map` was the only v6 policy hook).

  Unlike `table-map` (which gates only the kernel install and keeps a
  denied route visible in `show bgp ipv6`), an inbound route-map deny
  drops the route from the receiver's RIB entirely, and an outbound deny
  suppresses the advertisement at the originator.

  Policies are configured before the session establishes, so the test
  exercises the ingest / advertise policy hooks directly (no inbound
  soft-reconfiguration is assumed).

  Test Topology:
  ```
  ┌─────────────────┐   192.168.0.0/30    ┌─────────────────┐
  │       z1        │   2001:db8:12::/64   │       z2        │
  │     AS65001     ├─────────────────────┤     AS65002     │
  │ .1 / 12::1      │                     │ .2 / 12::2      │
  └─────────────────┘                     └─────────────────┘
  ```

  z1 originates 2001:db8:100::/48, :200::/48, :300::/48 and binds an
  OUTBOUND policy OUT6 that denies :300::/48. z2 binds an INBOUND policy
  IN6 that denies :100::/48 and stamps `set med 50` on :200::/48.

  Expected at z2: only :200::/48 survives — :100::/48 is dropped by z2's
  inbound deny, :300::/48 is never advertised by z1's outbound deny —
  and :200::/48 carries the inbound-stamped MED into the FIB.

  Scenario: Setup topology and verify inbound + outbound IPv6 route-map
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-out.yaml" to namespace "z1"
    And I apply config "z2-in.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp summary" in namespace "z2" should contain "Established"
    # z1 originates all three — the outbound policy gates advertisement,
    # not origination, so :300::/48 stays in z1's own RIB.
    And show command "show bgp ipv6" in namespace "z1" should contain "2001:db8:100::/48"
    And show command "show bgp ipv6" in namespace "z1" should contain "2001:db8:300::/48"
    # The permitted prefix flows end to end (proves v6 advertise/receive).
    And show command "show bgp ipv6" in namespace "z2" should contain "2001:db8:200::/48"
    # Inbound deny: z1 advertised :100::/48 but z2's IN6 drops it.
    And show command "show bgp ipv6" in namespace "z2" should not contain "2001:db8:100::/48"
    # Outbound deny: z1's OUT6 never advertises :300::/48 (z2 has no
    # matching inbound deny, so its absence isolates the outbound hook).
    And show command "show bgp ipv6" in namespace "z2" should not contain "2001:db8:300::/48"
    # Inbound set-med rewrote :200::/48's metric all the way into the FIB.
    And kernel route "2001:db8:200::/48" in namespace "z2" should eventually contain "metric 50"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
