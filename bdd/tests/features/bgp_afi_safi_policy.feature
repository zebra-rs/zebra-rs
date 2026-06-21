@serial
@bgp_afi_safi_policy
Feature: BGP per-AFI neighbor policy under afi-safi (peer-wide fallback)

  As a network operator I want to bind a route-policy per address family
  under `neighbor X afi-safi <name> policy {in,out}`. The per-neighbor
  peer-wide `neighbor X policy {in,out}` form has been retired; the only
  way to bind a peer-wide route-policy is now through a `neighbor-group`,
  which a neighbor inherits as a fallback across families. A per-AFI
  binding MUST take priority over the inherited peer-wide one for routes
  of that family.

  This is observed inbound on z2: z1 originates two /32s; z2's inbound
  policy decides which survive in z2's BGP table. Policy edits are picked
  up live (soft-reconfiguration inbound), no session reset.

  Test Topology:
  ```
  z1 (AS65001) ──eBGP── z2 (AS65002)
  192.168.0.1/24        192.168.0.2/24
  ```
  Both on bridge br0.

  Config files:
  - z1.yaml: AS65001, peers z2, originates 10.0.0.1/32 + 10.0.0.2/32.
  - z2-base.yaml: AS65002, peers z1, soft-reconfiguration inbound, no
    policy (both routes accepted).
  - z2-peerwide-deny.yaml: binds a peer-wide `policy in DENY-ALL` (deny
    everything) via a `neighbor-group` the peer inherits — both routes
    disappear.
  - z2-perafi-permit.yaml: adds `afi-safi ipv4 policy in PERMIT-ALL`
    while the inherited DENY-ALL stays bound — the per-AFI policy wins,
    routes return.

  Scenario: Setup sessions; with no policy both routes are accepted
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2-base.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z2" has "10.0.0.2/32"

  Scenario: Peer-wide policy inherited from a neighbor-group denies every inbound route
    Given the test topology exists
    When I apply config "z2-peerwide-deny.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" does not have "10.0.0.1/32"
    And BGP route in "z2" does not have "10.0.0.2/32"

  Scenario: A per-AFI ipv4 policy overrides the inherited peer-wide deny — routes return
    Given the test topology exists
    When I apply config "z2-perafi-permit.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP route in "z2" has "10.0.0.1/32"
    And BGP route in "z2" has "10.0.0.2/32"
    And show command "show bgp neighbor 192.168.0.1" in namespace "z2" should contain "ipv4: policy in PERMIT-ALL"
    And show command "show bgp neighbor 192.168.0.1" in namespace "z2" should contain "(peer-wide): policy in DENY-ALL"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
