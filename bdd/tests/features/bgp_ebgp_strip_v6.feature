@serial
@bgp_ebgp_strip_v6
Feature: BGP iBGP-only attributes are stripped on eBGP egress (IPv6 unicast)
  As a network operator
  I want the iBGP-only path attributes — ORIGINATOR_ID, CLUSTER_LIST and
  LOCAL_PREF — to stay inside the AS for IPv6 unicast routes too
  So that an iBGP-learned IPv6 route re-advertised to an eBGP peer does not
  leak attributes that have meaning only within the local AS.

  This is the IPv6 counterpart of @bgp_rr_ebgp_strip: the egress builder
  `route_update_ipv6` clones the route's stored attrs, so without the
  eBGP strip an iBGP-learned v6 route would carry ORIGINATOR_ID /
  CLUSTER_LIST (RFC 4456 §8) and LOCAL_PREF (RFC 4271 §5.1.5) across the
  AS boundary. Sessions are IPv6-transport so next-hop-self uses the
  session's local v6 address directly.

  Test Topology (IPv6 transport, 2001:db8::/64 link):
  ```
  ┌────────────────────────────────────────────────────────────────────────┐
  │                                  br0                                   │
  └────────┬──────────────────┬──────────────────┬──────────────────┬─────┘
           │                  │                  │                  │
      ┌────┴────┐        ┌────┴────┐        ┌────┴────┐        ┌────┴────┐
      │   z1    │  iBGP  │   z2    │        │   z3    │  eBGP  │   z4    │
      │  (RR)   │◀──────▶│(client) │        │(client) │◀──────▶│ (peer)  │
      │ AS65001 │        │ AS65001 │        │+ border │        │ AS65002 │
      │id 10.0. │        │id 10.0. │        │ AS65001 │        │id 10.0. │
      │   0.1   │        │   0.2   │        │id 10.0. │        │   0.4   │
      │2001:db8 │        │2001:db8 │        │   0.3   │        │2001:db8 │
      │   ::1   │        │   ::2   │        │2001:db8 │        │   ::4   │
      └────┬────┘        └─────────┘        │   ::3   │        └─────────┘
           │ iBGP (RR client)               └────┬────┘
           └─────────────────────────────────────┘
  ```
  - z1 is the route reflector; z2 and z3 are its clients (same AS 65001).
  - z2 originates 2001:db8:beef::/64 and advertises it to the RR (z1).
  - z1 REFLECTS the route to client z3, stamping ORIGINATOR_ID (z2's
    router-id 10.0.0.2) and CLUSTER_LIST (z1's cluster-id). z3 therefore
    sees the route WITH the iBGP-only attributes — the positive control.
  - z3 re-advertises the route to its eBGP peer z4 (AS 65002). z4 MUST
    receive the route WITHOUT ORIGINATOR_ID / CLUSTER_LIST / LOCAL_PREF.

  Config files:
  - z1.yaml: RR — iBGP to z2 and z3, both route-reflector clients.
  - z2.yaml: client — iBGP to z1; originates 2001:db8:beef::/64.
  - z3.yaml: client + border — iBGP to z1, eBGP to z4.
  - z4.yaml: eBGP peer — eBGP to z3 only.

  Scenario: Setup topology and establish BGP sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8::2/64" on bridge "br0"
    And I create namespace "z3" with IP "2001:db8::3/64" on bridge "br0"
    And I create namespace "z4" with IP "2001:db8::4/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "z4.yaml" to namespace "z4"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "2001:db8::2" should be "Established"
    And BGP session in "z1" to "2001:db8::3" should be "Established"
    And BGP session in "z2" to "2001:db8::1" should be "Established"
    And BGP session in "z3" to "2001:db8::1" should be "Established"
    And BGP session in "z3" to "2001:db8::4" should be "Established"
    And BGP session in "z4" to "2001:db8::3" should be "Established"

  Scenario: RR client z3 receives the reflected route WITH the iBGP-only attributes
    Given the test topology exists
    When I wait 15 seconds for BGP to operate
    Then show command "show bgp ipv6 2001:db8:beef::/64" in namespace "z3" should eventually contain "BGP routing table entry for 2001:db8:beef::/64"
    # ORIGINATOR_ID / CLUSTER_LIST stamped by the reflector (RFC 4456), and
    # LOCAL_PREF carried across the iBGP path (RFC 4271 §5.1.5).
    And show command "show bgp ipv6 2001:db8:beef::/64" in namespace "z3" should eventually contain "Originator: 10.0.0.2"
    And show command "show bgp ipv6 2001:db8:beef::/64" in namespace "z3" should contain "Cluster list:"
    And show command "show bgp ipv6 2001:db8:beef::/64" in namespace "z3" should contain "localpref"

  Scenario: eBGP peer z4 receives the route but NOT the iBGP-only attributes
    Given the test topology exists
    When I wait 15 seconds for BGP to operate
    # Positive guard first: prove the route is actually present (an unmatched
    # show command returns empty output, which would make a bare "should not
    # contain" pass vacuously).
    Then show command "show bgp ipv6 2001:db8:beef::/64" in namespace "z4" should eventually contain "BGP routing table entry for 2001:db8:beef::/64"
    # The iBGP-only attributes must not cross the AS boundary: ORIGINATOR_ID /
    # CLUSTER_LIST (RFC 4456) and LOCAL_PREF (RFC 4271 §5.1.5).
    And show command "show bgp ipv6 2001:db8:beef::/64" in namespace "z4" should not contain "Originator:"
    And show command "show bgp ipv6 2001:db8:beef::/64" in namespace "z4" should not contain "Cluster list:"
    And show command "show bgp ipv6 2001:db8:beef::/64" in namespace "z4" should not contain "localpref"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "z4"
    And I delete bridge "br0"
    Then the test environment should be clean
