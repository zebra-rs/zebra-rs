@serial
@bgp_update_group_live_policy_out
Feature: Binding an outbound policy on a live neighbor must re-form its update-group (IPv4)
  As a network operator
  I want `afi-safi ipv4 policy out` bound (or unbound) on an Established
  neighbor to take effect for that neighbor alone
  So that its group-mates keep receiving the routes the policy denies
  only to it, and the neighbor itself is filtered even when a group-mate
  is the one whose UPDATE gets built.

  An update-group is keyed by a signature of every per-peer egress input,
  and the outbound policy name is one of them. The signature is computed
  when a session reaches Established (and on an egress-script rebind),
  but binding a policy on a neighbor that is already Established only
  rewrote the policy slot: the neighbor stayed in the group its old,
  policy-less signature had put it in. From the next best-path change on,
  whichever member the memo builds on decides for all: if the bound
  neighbor is canonical, its deny is memoized and the plain group-mates
  never receive the route; if a plain member is canonical, the bound
  neighbor receives what its own policy denies.

  Test Topology (one bridge; z1 is the router under test):
  ```
  ┌───────────────────────────────────────────────────────┐
  │                          br0                          │
  └────┬──────────────┬──────────────┬──────────────┬─────┘
   ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐
   │  z2   │      │  z3   │      │  z1   │      │  z4   │
   │ iBGP  │      │ iBGP  │      │  DUT  │      │ eBGP  │
   │  .2   │      │  .3   │      │  .1   │      │  .4   │
   └───────┘      └───────┘      └───────┘      └───────┘
  ```
  Session addresses are 192.168.70.N; router-ids 10.70.0.N. z2 and z3
  share z1's local address, so they start in one IPv4-unicast group; z2
  has the lower peer index and is the canonical member.

  - z4 originates 10.40.1.0/24 from the start; both z2 and z3 hold it.
  - While every session is Established, z1 binds `policy out DENY-P2`
    (deny 10.40.2.0/24, permit the rest) toward z2 only.
  - z4 then adds 10.40.2.0/24: z3 must receive it, z2 must not.
  - z1 unbinds the policy: z2 rejoins z3's group and receives
    10.40.2.0/24 through the re-sync; z4's third prefix reaches both.

  Config files:
  - z1.yaml: no policy; z1-deny-z2.yaml: policy bound toward z2;
    z1-undeny.yaml: policy defined but not bound.
  - z2.yaml, z3.yaml: listeners.
  - z4.yaml / z4-two.yaml / z4-three.yaml: one, two, three prefixes.

  Scenario: Setup topology; both iBGP neighbors share one update-group and hold the first prefix
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.70.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.70.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.70.3/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.70.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "z4.yaml" to namespace "z4"
    Then BGP session in "z1" to "192.168.70.2" should eventually be "Established"
    And BGP session in "z1" to "192.168.70.3" should eventually be "Established"
    And BGP session in "z1" to "192.168.70.4" should eventually be "Established"
    And show command "show bgp" in namespace "z2" should eventually contain "10.40.1.0/24"
    And show command "show bgp" in namespace "z3" should eventually contain "10.40.1.0/24"
    And show command "show bgp update-group" in namespace "z1" should eventually contain "2 groups, 3 members."

  Scenario: Binding an outbound policy on the live neighbor moves it into its own update-group
    Given the test topology exists
    When I apply config "z1-deny-z2.yaml" to namespace "z1"
    # z2 (policy DENY-P2), z3 (no policy) and z4 (eBGP) now have three
    # distinct signatures. Without the re-grouping z2 stays with z3.
    Then show command "show bgp update-group" in namespace "z1" should eventually contain "3 groups, 3 members."

  Scenario: A prefix the policy denies to the bound neighbor still reaches its former group-mate
    Given the test topology exists
    When I apply config "z4-two.yaml" to namespace "z4"
    # The new best path runs through the memo. Sharing z2's group, z3
    # would inherit z2's deny and never receive the prefix.
    Then show command "show bgp" in namespace "z3" should eventually contain "10.40.2.0/24"
    And show command "show bgp" in namespace "z2" should not contain "10.40.2.0/24"
    And show command "show bgp" in namespace "z2" should contain "10.40.1.0/24"

  Scenario: Unbinding the policy on the live neighbor merges it back and re-syncs it
    Given the test topology exists
    When I apply config "z1-undeny.yaml" to namespace "z1"
    Then show command "show bgp update-group" in namespace "z1" should eventually contain "2 groups, 3 members."
    And show command "show bgp" in namespace "z2" should eventually contain "10.40.2.0/24"
    When I apply config "z4-three.yaml" to namespace "z4"
    Then show command "show bgp" in namespace "z2" should eventually contain "10.40.3.0/24"
    And show command "show bgp" in namespace "z3" should eventually contain "10.40.3.0/24"

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
