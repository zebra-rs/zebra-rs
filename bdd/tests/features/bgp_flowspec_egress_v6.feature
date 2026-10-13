@serial
@bgp_flowspec_egress_v6
Feature: Flowspec egress honours the shared gates (IPv6)
  As a network operator relaying BGP Flow Specification rules
  I want a flow spec's communities to limit where it goes, a neighbor the
  rule no longer reaches to lose it, and a neighbor that comes up later to
  be sent the rules already held
  So flow-spec rules propagate exactly as the other families' routes do.

  Flowspec egress skipped the checks every other family applies: a rule
  carrying NO_ADVERTISE or NO_EXPORT was sent to every neighbor (RFC
  1997); a neighbor the new best no longer reached kept the previous copy;
  and the session-up dump had no Flowspec step, so a neighbor that came up
  after the rules were learned never got them. The twin is
  `bgp_flowspec_egress`; this one carries IPv6 flow specs (RFC 8956).

  Test Topology:
  ```
  ┌──────────────────────────────────────────────────────────────────────┐
  │                        br0 192.168.67.0/24                           │
  └─────┬─────────────┬──────────────┬──────────────┬──────────────┬─────┘
   ┌────┴────┐   ┌────┴────┐    ┌────┴────┐    ┌────┴────┐    ┌────┴────┐
   │   z1    │   │   h1    │    │   z2    │    │   z3    │    │   z4    │
   │  (DUT)  │   │ scripted│    │  eBGP   │    │  iBGP   │    │  eBGP   │
   │ AS65001 │   │ AS65001 │    │ AS65002 │    │ AS65001 │    │ AS65004 │
   │  .1     │   │  .2     │    │  .3     │    │  .4     │    │  .5 late│
   └─────────┘   └─────────┘    └─────────┘    └─────────┘    └─────────┘
  ```
  h1 (tests/scripts/bgp_flowspec_send.py) announces three destination-prefix
  rules: 2001:db8:27:3::/64 with NO_ADVERTISE, 2001:db8:27:2::/64 with NO_EXPORT and 2001:db8:27:1::/64 with no
  community, in that order. h1 is an iBGP route-reflector client of z1 and
  originates the rules (empty AS_PATH), so they pass RFC 9117 validation.

  Config files:
  - z1.yaml: DUT — flowspec-ipv6 to h1 (passive, a reflector client), z2, z3 and z4.
  - z2.yaml, z3.yaml, z4.yaml: flowspec-ipv6 to z1.

  Scenario: Setup; rule 1 reaches every neighbor
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.67.1/24" on bridge "br0"
    And I create namespace "h1" with IP "192.168.67.2/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.67.3/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.67.4/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.67.5/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    Then BGP session in "z1" to "192.168.67.3" should eventually be "Established"
    And BGP session in "z1" to "192.168.67.4" should eventually be "Established"
    When I spawn "timeout 600 python3 tests/scripts/bgp_flowspec_send.py 192.168.67.1 65001 192.168.67.2 6 /tmp/bgp_flowspec_egress_v6 ibgp" in namespace "h1"
    Then BGP session in "z1" to "192.168.67.2" should eventually be "Established"
    And show command "show bgp flowspec ipv6" in namespace "z1" should eventually contain "dst 2001:db8:27:1::/64"
    And show command "show bgp flowspec ipv6" in namespace "z1" should contain "dst 2001:db8:27:3::/64"
    # Rule 1, sent last, has reached both neighbors: so have the others.
    And show command "show bgp flowspec ipv6" in namespace "z2" should eventually contain "dst 2001:db8:27:1::/64"
    And show command "show bgp flowspec ipv6" in namespace "z3" should eventually contain "dst 2001:db8:27:1::/64"

  Scenario: A rule carrying NO_EXPORT stays inside the AS
    Given the test topology exists
    Then show command "show bgp flowspec ipv6" in namespace "z3" should contain "dst 2001:db8:27:2::/64"
    # Pre-fix the eBGP neighbor got it too.
    And show command "show bgp flowspec ipv6" in namespace "z2" should not contain "dst 2001:db8:27:2::/64"

  Scenario: A rule carrying NO_ADVERTISE goes to no neighbor
    Given the test topology exists
    # Pre-fix both neighbors got it.
    Then show command "show bgp flowspec ipv6" in namespace "z2" should not contain "dst 2001:db8:27:3::/64"
    And show command "show bgp flowspec ipv6" in namespace "z3" should not contain "dst 2001:db8:27:3::/64"

  Scenario: A neighbor that comes up later is sent the rules already held
    Given the test topology exists
    When I start zebra-rs in namespace "z4"
    And I apply config "z4.yaml" to namespace "z4"
    Then BGP session in "z1" to "192.168.67.5" should eventually be "Established"
    # Pre-fix the session-up dump sent no flow spec.
    And show command "show bgp flowspec ipv6" in namespace "z4" should eventually contain "dst 2001:db8:27:1::/64"

  Scenario: A rule its new best no longer lets out is withdrawn from every neighbor
    Given the test topology exists
    When I execute "touch /tmp/bgp_flowspec_egress_v6.noadv1" in namespace "h1"
    # Pre-fix the neighbors were skipped and kept rule 1.
    Then show command "show bgp flowspec ipv6" in namespace "z2" should eventually not contain "dst 2001:db8:27:1::/64"
    And show command "show bgp flowspec ipv6" in namespace "z3" should eventually not contain "dst 2001:db8:27:1::/64"
    And show command "show bgp flowspec ipv6" in namespace "z4" should eventually not contain "dst 2001:db8:27:1::/64"
    And show command "show bgp flowspec ipv6" in namespace "z1" should contain "dst 2001:db8:27:1::/64"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I delete namespace "z1"
    And I delete namespace "h1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "z4"
    And I delete bridge "br0"
    Then the test environment should be clean
