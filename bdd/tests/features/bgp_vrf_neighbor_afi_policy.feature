@serial
@bgp_vrf_neighbor_afi_policy
Feature: Per-VRF BGP neighbor per-AFI policy and prefix-set filters
  As an operator of an L3VPN PE
  I want `router bgp vrf <name> neighbor <addr> afi-safi ipv4
  {policy|prefix-set} {in|out}` to filter CE routes
  So that inbound and outbound route policy works on a per-VRF CE
  neighbor exactly as it does on a global neighbor — through the
  per-VRF policy-actor plumbing (`bgp-vrf:<name>` proto,
  `peer_policy_ident`), not just at the global scope.

  One scenario per binding. CE1 advertises 10.0.1.1..5/32 into vrf-cust.
  PE1's inbound filters on the CE1 neighbor drop .2 (prefix-set-in, a
  permit-list omitting it) and .3 (policy-in). PE1 re-advertises the VRF
  Loc-RIB to CE2, where the outbound filters on the CE2 neighbor drop .4
  (prefix-set-out) and .5 (policy-out). .1 survives every filter and is
  the control.

  Test Topology (3 namespaces):
  ```
   ce1 ────────── pe1 ────────── ce2
   AS 65001    AS 65000        AS 65002
   nets .1..5   vrf-cust        receiver
        .2 ── .1        .1 ── .2
       10.1.0.0/30    10.2.0.0/30
  ```

  Scenario: Build the per-AFI policy VRF topology
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
    Then BGP session in "ce1" to "10.1.0.1" should eventually be "Established"
    And BGP session in "ce2" to "10.2.0.1" should eventually be "Established"

  Scenario: prefix-set in drops a CE prefix before the VRF Loc-RIB
    # The permit-list PS-IN omits 10.0.1.2/32, so the inbound prefix-set
    # binding denies it; the control .1 (a member) is accepted.
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust" in namespace "pe1" should eventually contain "10.0.1.1/32"
    And show command "show bgp vrf vrf-cust" in namespace "pe1" should not contain "10.0.1.2/32"

  Scenario: policy in denies a CE prefix into the VRF Loc-RIB
    # PL-IN denies 10.0.1.3/32 (which PS-IN permits, so this isolates the
    # policy-list effect); .4 passes both inbound filters as a control.
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust" in namespace "pe1" should eventually contain "10.0.1.4/32"
    And show command "show bgp vrf vrf-cust" in namespace "pe1" should not contain "10.0.1.3/32"

  Scenario: prefix-set out withholds a VRF route from a CE neighbor
    # 10.0.1.4/32 is present in PE1's VRF Loc-RIB but PS-OUT (bound out on
    # the CE2 neighbor) omits it, so it is never advertised to CE2. The
    # control .1 is advertised, proving the re-advertisement path itself
    # works.
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust" in namespace "pe1" should contain "10.0.1.4/32"
    And show command "show bgp" in namespace "ce2" should eventually contain "10.0.1.1/32"
    And show command "show bgp" in namespace "ce2" should not contain "10.0.1.4/32"

  Scenario: policy out withholds a VRF route from a CE neighbor
    # 10.0.1.5/32 is present in the VRF Loc-RIB and permitted by PS-OUT,
    # but PL-OUT denies it outbound, so CE2 never receives it — isolating
    # the outbound policy-list effect from the outbound prefix-set.
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust" in namespace "pe1" should contain "10.0.1.5/32"
    And show command "show bgp" in namespace "ce2" should not contain "10.0.1.5/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "ce2"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    And I delete namespace "ce2"
    Then the test environment should be clean
