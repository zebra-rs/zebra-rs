@serial
@bgp_unnumbered_incremental
Feature: Routes appearing after establishment reach an IPv6-unnumbered peer
  As a network operator running BGP over IPv6-only point-to-point links
  I want routes that show up while an interface-keyed (unnumbered)
  session is already Established to be advertised to that peer, so
  convergence on unnumbered fabrics does not depend on session resets.

  Regression guard: every incremental advertise fan-out collected
  peers by remote address (`PeerMap::iter()` + `get_mut(&addr)`),
  which silently skips `PeerKey::Interface` peers — an unnumbered
  peer's remote link-local is never written into the address map. An
  interface-keyed session received the initial `route_sync` dump at
  establishment and then nothing: no reach, no withdraws, in any
  family. The fan-outs now collect peer idents over `iter_all()`,
  which is key-agnostic.

  Topology: the bgp_unnumbered_neighbor P2P link (link-local only,
  RA-discovered interface-neighbor on both ends, IPv4 carried via
  RFC 8950 ENHE). The route under test is a `network` statement
  applied only AFTER the session is verified Established, so it can
  only reach the peer through the incremental path (initial-config
  networks ride the route_sync dump, which always worked).
  adv-interval is pinned to 1s in the configs — the incremental
  reach flushes through the update-group debounce.

  Scenario: Setup topology
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-base.yaml" to namespace "z1"
    And I apply config "z2-base.yaml" to namespace "z2"
    And I wait 2 seconds
    And I apply config "z1-full.yaml" to namespace "z1"
    And I apply config "z2-full.yaml" to namespace "z2"
    Then BGP session in namespace "z1" should eventually be "Established"
    And BGP session in namespace "z2" should eventually be "Established"
    And I wait 5 seconds
    # Baseline: the initial-config networks crossed via route_sync
    # (this path always worked — it is not the subject of the test).
    And BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z1" has "10.0.0.2/32"

  Scenario: A network added after Established reaches the unnumbered peer
    Given the test topology exists
    When I apply command "set router bgp afi-safi ipv4 network 10.99.1.0/24" in namespace "z1"
    And I wait 8 seconds
    # Origination on z1.
    Then BGP route in "z1" has "10.99.1.0/24"
    # The incremental advertisement must arrive at the interface-keyed
    # peer: before the fix the addr-keyed fan-out never visited it and
    # this prefix never arrived.
    And BGP route in "z2" has "10.99.1.0/24"

  Scenario: A network removed after Established is withdrawn from the unnumbered peer
    Given the test topology exists
    When I apply command "delete router bgp afi-safi ipv4 network 10.99.1.0/24" in namespace "z1"
    And I wait 8 seconds
    Then show command "show bgp" in namespace "z2" should not contain "10.99.1.0/24"
    # Guard against a vacuous pass of the negative assertion above: the
    # same table must still carry z1's initial network.
    And show command "show bgp" in namespace "z2" should contain "10.0.0.1/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
