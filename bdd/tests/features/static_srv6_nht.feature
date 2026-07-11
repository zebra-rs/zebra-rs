@static_srv6_nht
Feature: Static route inherits SRv6 segments from its covering route
  As a network operator
  I want a static route whose gateway is reachable only through a
  BGP-over-SRv6 service route to resolve recursively through it and
  inherit the H.Encap segment list — the SRv6 analog of the SR-MPLS
  label inheritance in @isis_srmpls.

  Test Topology (three veth pairs, iBGP z1<->z3 across a transit core):
  ```
  ┌────┐ eth0 ── i2 ┌────────┐ i1 ──────── i1 ┌────────┐ i2 ─────── i1 ┌────────┐
  │ h1 │────────────│   z1   │────────────────│   z2   │───────────────│   z3   │
  └────┘3001:db8::/64 egress │2001:db8:12::/64│  core  │2001:db8:23::/64 ingress│
   3001:db8::1      │ LOC1   │                │        │               │        │
                    └────────┘                └────────┘               └────────┘
   cust0 on z1: 2001:db8:cafe::1/64      z2 knows ONLY the two links
   (dummy — the gateway anchor)          and z1's locator fcbb:bbbb:1::/48
  ```

  - z1 advertises locator LOC1 (fcbb:bbbb:1::/48) and redistributes
    connected into BGP with `segment-routing srv6 ipv6-unicast`, so its
    prefixes (h1's subnet, the cust0 anchor) carry the End.DT6 SID
    fcbb:bbbb:1:40::.
  - z3 receives them over `encapsulation-type srv6` and installs
    H.Encaps service routes.
  - The static under test on z3, `3001:db8::1/128 via 2001:db8:cafe::1`,
    has a gateway covered ONLY by the 2001:db8:cafe::/64 SRv6 route:
    NHT must resolve through it and inherit that route's segment list.
    The transit core z2 knows nothing about the service prefixes, so
    the end-to-end ping to the host h1 behind z1 proves the inherited
    encapsulation carried the traffic (decap at z1's End.DT6, plain
    IPv6 delivery to h1).
  - Deleting the static releases its seg6 nexthop group and forwarding
    falls back to the BGP /64 covering h1's subnet.

  Config files (in `bdd/tests/configs/static_srv6_nht/`):
  - z1.yaml, z2.yaml, z3.yaml

  Scenario: Setup topology and converge BGP over SRv6
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I create namespace "z3"
    And I create namespace "h1"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I connect namespace "z2" interface "i2" to namespace "z3" interface "i1"
    And I connect namespace "z1" interface "i2" to namespace "h1" interface "eth0"
    And I add address "3001:db8::1/64" to interface "eth0" in namespace "h1"
    And I add route "2001:db8:23::/64" via "3001:db8::2" in namespace "h1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I create dummy interface "cust0" with address "2001:db8:cafe::1/64" in namespace "z1"
    And I wait 40 seconds
    # The covering service route arrived and installed as SRv6 H.Encaps.
    Then show command "show ipv6 route 2001:db8:cafe::/64" in namespace "z3" should eventually contain "via seg6"
    And show command "show ipv6 route 2001:db8:cafe::/64" in namespace "z3" should contain "fcbb:bbbb:1:40::"

  Scenario: Static route resolves through the SRv6 route and inherits its segments
    Given the test topology exists
    When I apply command "set router static ipv6 route 3001:db8::1/128 nexthop 2001:db8:cafe::1" in namespace "z3"
    # The gateway is not on-link: NHT resolves it through the SRv6
    # service route — rendered FRR-style as a recursive two-liner with
    # the inherited segment list on the resolved line.
    Then show command "show ipv6 route 3001:db8::1/128" in namespace "z3" should eventually contain "via 2001:db8:cafe::1 (recursive)"
    # The kernel forwards the static prefix with the inherited H.Encap.
    And kernel route "3001:db8::1" in namespace "z3" should eventually contain "encap seg6"
    And kernel route "3001:db8::1" in namespace "z3" should eventually contain "fcbb:bbbb:1:40::"
    And kernel route "3001:db8::1" in namespace "z3" should eventually contain "proto static"
    # End-to-end: z2 cannot route the inner destination, so a reply
    # from h1 proves the packet crossed the core inside the inherited
    # SRv6 encapsulation and was decapsulated by z1's End.DT6 SID.
    And ping from "z3" to "3001:db8::1" should succeed

  Scenario: Deleting the static falls back to the covering BGP route
    Given the test topology exists
    When I apply command "delete router static ipv6 route 3001:db8::1/128" in namespace "z3"
    # The /128 leaves the kernel (its seg6 nexthop-group reference is
    # released); forwarding falls back to the BGP /64 for h1's subnet,
    # still SRv6-encapsulated.
    Then kernel route "3001:db8::1" in namespace "z3" should eventually be gone
    And kernel route "3001:db8::/64" in namespace "z3" should eventually contain "proto bgp"
    And kernel route "3001:db8::/64" in namespace "z3" should eventually contain "encap seg6"
    And ping from "z3" to "3001:db8::1" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "h1"
    Then the test environment should be clean
