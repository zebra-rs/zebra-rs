@serial
@bgp_vrf_self_network
Feature: Per-VRF self-originated `network` reaches CE neighbors
  As an operator of an L3VPN PE
  I want a `network` under `router bgp vrf X afi-safi {ipv4,ipv6}` to be
  advertised to the VRF's CE (unicast) neighbors
  So that a PE can originate a prefix into a customer VRF without a
  static route + redistribute workaround.

  Regression guard for two bugs:

  1. Split-horizon collision — the self-originated Loc-RIB row carried
     ident 0, which aliased the first CE enrolled in the VRF PeerMap
     (also ident 0), so the egress split-horizon (`route_update_ipv4`:
     `rib.ident == ctx.ident`) dropped the route to that peer. The row
     now carries `ORIGINATED_PEER`, like the redistribute path. The ipv4
     neighbor is enrolled first (ident 0) so the config-file scenarios
     exercise the exact collision that used to fail.

  2. Runtime edits were never advertised — `originate_self_network_*` /
     `withdraw_self_network_*` only wrote the Loc-RIB and emitted the
     VPNv4/v6 export, relying on the session-up sync to reach CE peers.
     That works for a config-file `network` (no session is up yet) but a
     `network` added to, or removed from, an already-Established session
     never reached the CE. Both now advertise like the import path.

  Test Topology (2 namespaces, point-to-point, dual-stack):
  ```
   ce1 ───────────────── pe1
   AS 65001            AS 65000
   global              vrf-cust (RD 65000:1)
                        network 10.9.0.0/24
                        network 2001:db8:9::/64
        .2 ── .1   (10.1.0.0/30)
        ::2 ── ::1 (2001:db8:1::/64)
  ```

  Config files:
  - pe1.yaml: AS 65000, vrf-cust with ipv4 (10.1.0.2) + ipv6 (2001:db8:1::2)
    CE neighbors, originating `network 10.9.0.0/24` and
    `network 2001:db8:9::/64`.
  - ce1.yaml: AS 65001, global neighbors to the PE (ipv4 + ipv6).

  Scenario: Build the PE-CE dual-stack topology and establish sessions
    Given a clean test environment
    When I create namespace "ce1"
    And I create namespace "pe1"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I start zebra-rs in namespace "ce1"
    And I start zebra-rs in namespace "pe1"
    And I apply config "ce1.yaml" to namespace "ce1"
    And I apply config "pe1.yaml" to namespace "pe1"
    Then show command "show bgp vrf" in namespace "pe1" should eventually contain "vrf-cust"
    And BGP session in "ce1" to "10.1.0.1" should eventually be "Established"
    And BGP session in "ce1" to "2001:db8:1::1" should eventually be "Established"

  Scenario: CE receives the PE's self-originated ipv4 network (ident-0 peer)
    Given the test topology exists
    Then show command "show bgp ipv4" in namespace "ce1" should eventually contain "10.9.0.0/24"

  Scenario: CE receives the PE's self-originated ipv6 network
    Given the test topology exists
    Then show command "show bgp ipv6" in namespace "ce1" should eventually contain "2001:db8:9::/64"

  Scenario: An ipv4 network added at runtime is advertised to the CE
    # The session is already Established, so the session-up sync cannot
    # carry this one — `originate_self_network_v4` must advertise it.
    Given the test topology exists
    When I apply command "set router bgp vrf vrf-cust afi-safi ipv4 network 10.9.1.0/24" in namespace "pe1"
    Then show command "show bgp ipv4" in namespace "ce1" should eventually contain "10.9.1.0/24"

  Scenario: Removing the runtime ipv4 network withdraws it from the CE
    Given the test topology exists
    When I apply command "delete router bgp vrf vrf-cust afi-safi ipv4 network 10.9.1.0/24" in namespace "pe1"
    Then show command "show bgp ipv4" in namespace "ce1" should eventually not contain "10.9.1.0/24"
    And show command "show bgp ipv4" in namespace "ce1" should contain "10.9.0.0/24"

  Scenario: An ipv6 network added at runtime is advertised to the CE
    Given the test topology exists
    When I apply command "set router bgp vrf vrf-cust afi-safi ipv6 network 2001:db8:9:1::/64" in namespace "pe1"
    Then show command "show bgp ipv6" in namespace "ce1" should eventually contain "2001:db8:9:1::/64"

  Scenario: Removing the runtime ipv6 network withdraws it from the CE
    Given the test topology exists
    When I apply command "delete router bgp vrf vrf-cust afi-safi ipv6 network 2001:db8:9:1::/64" in namespace "pe1"
    Then show command "show bgp ipv6" in namespace "ce1" should eventually not contain "2001:db8:9:1::/64"
    And show command "show bgp ipv6" in namespace "ce1" should contain "2001:db8:9::/64"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    Then the test environment should be clean
