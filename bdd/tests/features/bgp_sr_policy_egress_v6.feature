@serial
@bgp_sr_policy_egress_v6
Feature: SR Policy egress carries a well-formed AS_PATH (IPv6)
  As a network operator distributing SR Policies over BGP (SAFI 73)
  I want our own and reflected policies to carry a well-formed AS_PATH
  So every neighbor accepts them, as RFC 4271 requires.

  Our own SR Policies went out with no AS_PATH at all (a missing
  well-known attribute) and a reflected policy went to an eBGP neighbor
  without our AS prepended (RFC 4271 §5.1.2): a neighbor running
  `enforce-first-as` rejected both. (A neighbor that comes up later is
  still sent our own policies only; replaying reflected ones needs a store
  of received policies, a follow-up.) The twin is
  `bgp_sr_policy_egress`; this one uses IPv6 endpoints.

  Test Topology:
  ```
   z4 (AS65004) ── eBGP ── z1 (AS65000) ── iBGP ── z2 (AS65000, RR) ── eBGP ── z3 (AS65003)
   enforce-first-as         origin        client                      enforce-first-as
  ```
  All four on bridge br0 10.0.69.0/24. z1 originates two policies, each
  consumed by the neighbor whose router-id is its Route Target (RFC 9830
  §4.2): GREEN for z3 (reflected by z2 onto eBGP) and BLUE for z4 (direct
  eBGP).

  Config files:
  - z1.yaml: the two policies; iBGP to z2 (its RR), eBGP to z4.
  - z2.yaml: route reflector — z1 a client, eBGP to z3.
  - z3.yaml, z4.yaml: enforce-first-as toward their neighbor.

  Scenario: Setup; the sessions come up
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "10.0.69.1/24" on bridge "br0"
    And I create namespace "z2" with IP "10.0.69.2/24" on bridge "br0"
    And I create namespace "z3" with IP "10.0.69.3/24" on bridge "br0"
    And I create namespace "z4" with IP "10.0.69.4/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "z4.yaml" to namespace "z4"
    # z2 reflects a policy only to the sessions up when it arrives (a late
    # neighbor is not sent it yet): bring z3 up before z1 originates.
    Then BGP session in "z2" to "10.0.69.3" should eventually be "Established"
    When I apply config "z1.yaml" to namespace "z1"
    Then BGP session in "z1" to "10.0.69.2" should eventually be "Established"
    And BGP session in "z1" to "10.0.69.4" should eventually be "Established"

  Scenario: Our own policy is accepted by the eBGP neighbor
    Given the test topology exists
    # Pre-fix z1's own policy carried no AS_PATH and z4 rejected it.
    Then show command "show bgp sr-policy ipv6" in namespace "z4" should eventually contain "endpoint 2001:db8:69::4"

  Scenario: A reflected policy is accepted by the eBGP neighbor
    Given the test topology exists
    # Pre-fix z2 reflected it to eBGP without its AS and z3 rejected it.
    Then show command "show bgp sr-policy ipv6" in namespace "z3" should eventually contain "endpoint 2001:db8:69::3"

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
