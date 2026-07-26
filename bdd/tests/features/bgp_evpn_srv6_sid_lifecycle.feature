@serial
@bgp_evpn_srv6_sid_lifecycle
Feature: EVPN-over-SRv6 L2 service SIDs track the locator's lifecycle
  As a network operator whose SRv6 locator is configured, moved or removed
  independently of the EVPN service
  I want the per-VNI End.DT2U / End.DT2M SIDs to be (re)attached to the
  already-originated Type-2 / Type-3 routes whenever the locator's usable
  prefix changes, so a locator that resolves late — or moves, or goes away
  — never leaves the peer holding a route pointing at a SID that was never
  carved or no longer exists.

  This is the reconcile documented in `Bgp::process_sr_rx`: on a material
  prefix change it re-seeds the SID pool and re-originates every MAC route
  and IMET so the SIDs follow. Route origination and locator resolution
  are independent events, so all three orderings are reachable in practice
  and none of them had coverage.

  z1 deliberately starts with `advertise-all-vni` + `encapsulation srv6`
  but NO locator object — its BGP instance references LOC1 before LOC1
  exists. z2's locator resolves normally throughout, so it is a stable
  observer: its own SIDs render as "Local SID" and z1's as "Remote SID",
  which is what lets a missing-SID assertion on z2 be specifically about
  z1's routes.

  ```
   z1 [br10: vxlan10 + host0]  ══════  z2 [br10: vxlan10]
      LOC1: absent -> :1: -> :9: -> absent      LOC2 fcbb:bbbb:2::/48
  ```

  Config files (in `bdd/tests/configs/bgp_evpn_srv6_sid_lifecycle/`):
  - z1-nolocator.yaml — references LOC1, which does not exist yet.
  - z2.yaml — LOC2 resolved from the start.

  Scenario: Setup with z1's locator absent
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1z2" to namespace "z2" interface "z2z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-nolocator.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I execute "ip link add br10 type bridge" in namespace "z1"
    And I execute "ip link set vxlan10 master br10" in namespace "z1"
    And I execute "ip link set br10 up" in namespace "z1"
    And I execute "ip link add host0 type dummy" in namespace "z1"
    And I execute "ip link set host0 master br10" in namespace "z1"
    And I execute "ip link set host0 up" in namespace "z1"
    And I execute "ip link add br10 type bridge" in namespace "z2"
    And I execute "ip link set vxlan10 master br10" in namespace "z2"
    And I execute "ip link set br10 up" in namespace "z2"
    And I wait 12 seconds for BGP to operate
    Then BGP session in "z1" to "2001:db8:12::2" should be "Established"

  Scenario: Routes originated before the locator resolves go out SID-less
    Given the test topology exists
    When I execute "bridge fdb add aa:bb:cc:dd:ee:01 dev host0 master static" in namespace "z1"
    # The routes themselves are originated — the missing locator must not
    # suppress the service, only its SIDs.
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "aa:bb:cc:dd:ee:01"
    # z2's own SIDs are Local; z1 is the only remote, and it has none yet.
    And show command "show bgp evpn" in namespace "z2" should not contain "Remote SID:"
    And show command "show bgp evpn" in namespace "z2" should contain "Local SID: fcbb:bbbb:2:"

  Scenario: Creating the locator re-originates the routes with their SIDs
    Given the test topology exists
    When I apply command "set segment-routing locator LOC1 prefix fcbb:bbbb:1::/48" in namespace "z1"
    And I apply command "set segment-routing locator LOC1 behavior usid" in namespace "z1"
    # The already-advertised IMET and MAC route are re-originated carrying
    # the freshly carved SIDs — no session bounce, no re-learn.
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "Remote SID: fcbb:bbbb:1:"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "(End.DT2M)"
    And show command "show bgp evpn" in namespace "z2" should eventually contain "(End.DT2U)"
    And show command "show l2 mac table" in namespace "z2" should eventually contain "fcbb:bbbb:1:"
    And BGP session in "z2" to "2001:db8:12::1" should be "Established"

  Scenario: Moving the locator prefix re-carves the SIDs under the new one
    Given the test topology exists
    When I apply command "set segment-routing locator LOC1 prefix fcbb:bbbb:9::/48" in namespace "z1"
    # A stale SID under the old prefix would be a black hole: the peer
    # would keep encapsulating toward a SID z1 no longer decapsulates.
    Then show command "show bgp evpn" in namespace "z2" should eventually contain "Remote SID: fcbb:bbbb:9:"
    And show command "show bgp evpn" in namespace "z2" should eventually not contain "Remote SID: fcbb:bbbb:1:"
    And show command "show l2 mac table" in namespace "z2" should eventually contain "fcbb:bbbb:9:"

  Scenario: Withdrawing the locator strips the SIDs but keeps the routes
    Given the test topology exists
    When I apply command "delete segment-routing locator LOC1" in namespace "z1"
    Then show command "show bgp evpn" in namespace "z2" should eventually not contain "Remote SID:"
    # The MAC is still local to z1 and the VNI still exists, so the
    # service survives the locator going away — only its SIDs are gone.
    And show command "show bgp evpn" in namespace "z2" should contain "aa:bb:cc:dd:ee:01"
    And BGP session in "z2" to "2001:db8:12::1" should be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
