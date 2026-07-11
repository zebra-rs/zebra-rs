@bgp_srv6_nht
Feature: BGP route inherits SRv6 segments from its covering route
  As a network operator
  I want a BGP route whose next-hop is reachable only through a
  BGP-over-SRv6 transport route to resolve recursively through it and
  inherit the H.Encap segment list — the BGP twin of the static-route
  inheritance in @static_srv6_nht, and the SRv6 analog of Inter-AS
  Option C (service routes riding a BGP-learned transport tunnel).

  Test Topology (three veth pairs, all AS 65000):
  ```
  ┌────────┐ i1 ── i2 ┌────────┐ i1 ──────── i1 ┌────────┐ i2 ─────── i1 ┌────────┐
  │   z4   │──────────│   z1   │────────────────│   z2   │───────────────│   z3   │
  │ service│ 2001:db8:│ egress │2001:db8:12::/64│  core  │2001:db8:23::/64 ingress│
  │  node  │ cafe::/64│ LOC1   │                │        │               │        │
  └────────┘          └────────┘                └────────┘               └────────┘
   lo: 3001:db8:100::1     z2 knows ONLY the links and z1's locator
   (service prefix          fcbb:bbbb:1::/48 — service prefixes cross
    aggregate via BGP)      it exclusively inside SRv6 encapsulation
  ```

  - Transport: z1<->z3 iBGP with `encapsulation-type srv6`; z1
    redistributes connected, so 2001:db8:cafe::/64 (the z1-z4 subnet)
    arrives at z3 as an SRv6 service route carrying z1's End.DT6 SID
    fcbb:bbbb:1:40::.
  - Service: z4<->z3 iBGP. The TCP session itself crosses the core
    inside the transport tunnel (encap at z3, decap at z1, plain
    delivery to z4). z4 redistributes its blackhole aggregate
    3001:db8:100::/64, which arrives at z3 with next-hop cafe::4 — an
    address covered ONLY by the SRv6 transport route. NHT resolves the
    next-hop through it and the installed route inherits the segment
    list: `proto bgp ... encap seg6 segs [fcbb:bbbb:1:40::]`.
  - The ping to z4's loopback proves the end-to-end datapath: z2
    cannot route the service prefix, so only the inherited
    encapsulation can carry the traffic.

  Config files (in `bdd/tests/configs/bgp_srv6_nht/`):
  - z1.yaml, z2.yaml, z3.yaml, z4.yaml

  Scenario: Setup topology and converge the SRv6 transport
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I create namespace "z3"
    And I create namespace "z4"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I connect namespace "z2" interface "i2" to namespace "z3" interface "i1"
    And I connect namespace "z1" interface "i2" to namespace "z4" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "z4.yaml" to namespace "z4"
    And I wait 40 seconds
    # The covering transport route arrived and installed as SRv6 H.Encaps.
    Then show command "show ipv6 route 2001:db8:cafe::/64" in namespace "z3" should eventually contain "via seg6"
    And show command "show ipv6 route 2001:db8:cafe::/64" in namespace "z3" should contain "fcbb:bbbb:1:40::"

  Scenario: Service route resolves through the SRv6 transport and inherits its segments
    Given the test topology exists
    # The z4 session establishes through the tunnel and delivers the
    # service aggregate; its next-hop cafe::4 is not on-link — NHT
    # resolves it through the SRv6 transport route.
    Then show command "show ipv6 route" in namespace "z3" should eventually contain "B  *> 3001:db8:100::/64"
    # The kernel forwards the service prefix with the inherited H.Encap
    # as a BGP route.
    And kernel route "3001:db8:100::/64" in namespace "z3" should eventually contain "encap seg6"
    And kernel route "3001:db8:100::/64" in namespace "z3" should eventually contain "fcbb:bbbb:1:40::"
    And kernel route "3001:db8:100::/64" in namespace "z3" should eventually contain "proto bgp"
    # End-to-end: z2 cannot route the inner destination, so a reply
    # from z4's loopback proves the packet crossed the core inside the
    # inherited SRv6 encapsulation and was decapsulated by z1.
    And ping from "z3" to "3001:db8:100::1" should succeed

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
    Then the test environment should be clean
