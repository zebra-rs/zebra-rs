@serial
@bgp_update_group_live_policy_out_v6
Feature: Binding an outbound policy on a live neighbor must re-form its update-group (IPv6)
  As a network operator
  I want `afi-safi ipv6 policy out` bound (or unbound) on an Established
  neighbor to take effect for that neighbor alone
  So that the neighbor itself is filtered even when a group-mate is the
  one whose UPDATE gets built, and its group-mates keep receiving what
  the policy denies only to it.

  IPv6 twin of `bgp_update_group_live_policy_out`. The outbound policy
  name is an update-group signature field, but the signature was only
  computed at Established, so a policy bound on a live neighbor left it
  in its old group and the memoized canonical outcome was shared.

  Here the policy is bound on the HIGHER-index member of the shared
  group (z3), the opposite of the IPv4 feature: z2, the canonical
  member, has no policy, so its permit is memoized and z3 receives the
  very prefix its own policy denies — the other direction of the same
  defect.

  Test Topology (one bridge; z1 is the router under test):
  ```
  ┌───────────────────────────────────────────────────────┐
  │                          br0                          │
  └────┬──────────────┬──────────────┬──────────────┬─────┘
   ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐
   │  z2   │      │  z3   │      │  z1   │      │  z4   │
   │ iBGP  │      │ iBGP  │      │  DUT  │      │ eBGP  │
   │  ::2  │      │  ::3  │      │  ::1  │      │  ::4  │
   └───────┘      └───────┘      └───────┘      └───────┘
  ```
  Session addresses are 2001:db8:70::N; router-ids 10.71.0.N. IPv4
  unicast is negotiated by default on every session too, so z1 also
  holds two ipv4-unicast groups (one iBGP pair, one eBGP) that an ipv6
  policy must not touch: the group counts below include them.

  - z4 originates 2001:db8:41::/64 from the start; both z2 and z3 hold it.
  - While every session is Established, z1 binds `policy out DENY-P2`
    (deny 2001:db8:42::/64, permit the rest) toward z3 only.
  - z4 then adds 2001:db8:42::/64: z2 must receive it, z3 must not.
  - z1 unbinds the policy: z3 rejoins z2's group and receives
    2001:db8:42::/64 through the re-sync; z4's third prefix reaches both.

  Config files:
  - z1.yaml: no policy; z1-deny-z3.yaml: policy bound toward z3;
    z1-undeny.yaml: policy defined but not bound.
  - z2.yaml, z3.yaml: listeners.
  - z4.yaml / z4-two.yaml / z4-three.yaml: one, two, three prefixes.

  Scenario: Setup topology; both iBGP neighbors share one update-group and hold the first prefix
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8:70::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8:70::2/64" on bridge "br0"
    And I create namespace "z3" with IP "2001:db8:70::3/64" on bridge "br0"
    And I create namespace "z4" with IP "2001:db8:70::4/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "z4.yaml" to namespace "z4"
    Then BGP session in "z1" to "2001:db8:70::2" should eventually be "Established"
    And BGP session in "z1" to "2001:db8:70::3" should eventually be "Established"
    And BGP session in "z1" to "2001:db8:70::4" should eventually be "Established"
    And show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:41::/64"
    And show command "show bgp ipv6" in namespace "z3" should eventually contain "2001:db8:41::/64"
    And show command "show bgp update-group" in namespace "z1" should eventually contain "4 groups, 6 members."

  Scenario: Binding an outbound policy on the live neighbor moves it into its own IPv6-unicast update-group
    Given the test topology exists
    When I apply config "z1-deny-z3.yaml" to namespace "z1"
    # The IPv6 iBGP pair splits (z3 with DENY-P2, z2 without); the two
    # ipv4-unicast groups are untouched. Without the re-grouping z3
    # stays with z2.
    Then show command "show bgp update-group" in namespace "z1" should eventually contain "5 groups, 6 members."

  Scenario: The bound neighbor is filtered even though its former group-mate is the canonical member
    Given the test topology exists
    When I apply config "z4-two.yaml" to namespace "z4"
    # z2 (no policy) receives the prefix. Sharing z2's group, z3 would
    # inherit z2's permit and receive the prefix its own policy denies.
    Then show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:42::/64"
    And show command "show bgp ipv6" in namespace "z3" should not contain "2001:db8:42::/64"
    And show command "show bgp ipv6" in namespace "z3" should contain "2001:db8:41::/64"

  Scenario: Unbinding the policy on the live neighbor merges it back and re-syncs it
    Given the test topology exists
    When I apply config "z1-undeny.yaml" to namespace "z1"
    Then show command "show bgp update-group" in namespace "z1" should eventually contain "4 groups, 6 members."
    And show command "show bgp ipv6" in namespace "z3" should eventually contain "2001:db8:42::/64"
    When I apply config "z4-three.yaml" to namespace "z4"
    Then show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:43::/64"
    And show command "show bgp ipv6" in namespace "z3" should eventually contain "2001:db8:43::/64"

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
