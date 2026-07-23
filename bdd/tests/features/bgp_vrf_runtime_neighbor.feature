@serial
@bgp_vrf_runtime_neighbor
Feature: Per-VRF BGP neighbors applied to a running VRF at runtime
  As an operator of an L3VPN PE
  I want to add, reconfigure, and remove a `router bgp vrf <name>`
  neighbor on a VRF that is already running
  So that a customer-edge change takes effect on the live task without
  respawning it — CE1 keeps its session while CE2 is added, given BFD,
  and removed.

  Regression guard for the incremental per-VRF neighbor path (PR #2087)
  and its two follow-ups: TCP-AO re-subscribe on reconfigure (#2094) and
  live BFD for runtime-added neighbors (#2095). Before #2087 a neighbor
  edit either did nothing until the next respawn or reset every session
  in the VRF; these scenarios prove the edit is surgical.

  The whole point is that CE1's session must NOT flap while CE2 is
  churned: `runtime_structure_eq` keeps a neighbor-only edit off the
  respawn path, so CE1 is the "still Established" witness. CE2's BFD
  session appearing in `show bfd peers` after enable and disappearing
  after the neighbor delete guards the `AddPeer` BFD subscribe and the
  `remove_peer` / `UnsubscribeClient` teardown (a leaked session would
  linger).

  Test Topology (3 namespaces):
  ```
   ce1 ────────── pe1 ────────── ce2
   AS 65001    AS 65000        AS 65002
   lo          vrf-cust        lo
   10.0.1.1/32 RD 65000:1      10.0.2.1/32
        .2 ── .1        .1 ── .2
       10.1.0.0/30    10.2.0.0/30
  ```
  Both PE-CE interfaces are enslaved to vrf-cust from the start; only
  the BGP neighbor for CE2 is deferred and driven in at runtime with
  `vtyctl apply -c`.

  Scenario: Build the runtime-neighbor VRF topology
    Given a clean test environment
    When I create namespace "ce1"
    And I create namespace "pe1"
    And I create namespace "ce2"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I connect namespace "pe1" interface "ce2" to namespace "ce2" interface "pe1"
    And I start zebra-rs in namespace "ce1"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "ce2"
    And I apply config "ce1.yaml" to namespace "ce1"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "ce2.yaml" to namespace "ce2"
    And I wait 10 seconds for BGP to operate
    Then show command "show bgp vrf" in namespace "pe1" should contain "vrf-cust"
    And show command "show bgp vrf" in namespace "pe1" should contain "running"
    And BGP session in "ce1" to "10.1.0.1" should eventually be "Established"

  Scenario: Adding a neighbor at runtime brings it up without disturbing CE1
    # `AddPeer`: the CE2 neighbor is created on the live VRF task. CE2
    # comes up and its prefix lands in the shared Loc-RIB, while CE1 —
    # checked immediately after the edit, when a respawn's reconnect would
    # still be in flight — stays Established.
    Given the test topology exists
    When I apply command "set router bgp vrf vrf-cust neighbor 10.2.0.2 remote-as 65002" in namespace "pe1"
    Then BGP session in "ce2" to "10.2.0.1" should eventually be "Established"
    And BGP session in "ce1" to "10.1.0.1" should be "Established"
    And show command "show bgp vrf vrf-cust" in namespace "pe1" should eventually contain "10.0.2.1/32"
    And show command "show bgp vrf vrf-cust" in namespace "pe1" should contain "10.0.1.1/32"

  Scenario: Enabling BFD on a live neighbor subscribes a session
    # `ReconfigurePeer` toggling `bfd enabled`: the per-VRF task subscribes
    # a BFD session for CE2 without bouncing either BGP session (BFD is a
    # separate datapath). The session appears in `show bfd peers` even if it
    # never reaches Up (CE2 runs no BFD) — the point is that it is
    # subscribed, not leaked.
    Given the test topology exists
    When I apply command "set router bgp vrf vrf-cust neighbor 10.2.0.2 bfd enabled true" in namespace "pe1"
    Then show command "show bfd peers" in namespace "pe1" should eventually contain "10.2.0.2"
    And BGP session in "ce1" to "10.1.0.1" should be "Established"
    And BGP session in "ce2" to "10.2.0.1" should be "Established"

  Scenario: Removing a neighbor at runtime tears down its session, route, and BFD
    # `RemovePeer`: `route_clean` withdraws CE2's prefix from the VRF
    # Loc-RIB, the session drops, and the BFD subscription is dropped —
    # `show bfd peers` no longer lists 10.2.0.2 (guards the per-peer
    # unsubscribe; a leak would keep it). CE1 and its route are untouched.
    Given the test topology exists
    When I apply command "delete router bgp vrf vrf-cust neighbor 10.2.0.2" in namespace "pe1"
    Then show command "show bgp vrf vrf-cust" in namespace "pe1" should eventually not contain "10.0.2.1/32"
    And show command "show bfd peers" in namespace "pe1" should eventually not contain "10.2.0.2"
    And BGP session in "ce2" to "10.2.0.1" should eventually not be "Established"
    And BGP session in "ce1" to "10.1.0.1" should be "Established"
    And show command "show bgp vrf vrf-cust" in namespace "pe1" should contain "10.0.1.1/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "ce2"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    And I delete namespace "ce2"
    Then the test environment should be clean
