@serial
@bgp_addpath_ipv6
Feature: BGP AddPath Send for IPv6 unicast (RFC 7911)
  As a network operator
  I want a BGP speaker with two paths for one IPv6 prefix to advertise
  BOTH of them — each with its own path identifier — to a neighbor that
  negotiated AddPath, instead of only the best path.

  The IPv6-unicast twin of @bgp_addpath_ipv4. It exercises the
  IPv6-specific AddPath path: the per-candidate fan-out bucketed into
  the update-group cache (`flush_ipv6`) and the `adj_out.v6` path-id
  tracking used to withdraw precisely.

  Test Topology (all on br0, sessions over IPv6):
  ```
     2001:db8:beef::/64        2001:db8:beef::/64
      (origin AS65001)          (origin AS65002)
           z1 ──┐                  ┌── z2
       2001:db8: │  2001:db8:      │  2001:db8:
          ::1/64 └──→  ::3/64  ←───┘     ::2/64
                       z3 (AS65003)
                        │  add-path send-receive
                        ↓
                       z4 (AS65004)  2001:db8::4/64
  ```

  z3 learns 2001:db8:beef::/64 over eBGP from BOTH z1 (AS_PATH 65001)
  and z2 (AS_PATH 65002), so its Loc-RIB holds two candidate paths.
  With AddPath Send negotiated toward z4, z3 advertises both — so z4
  sees TWO paths for the prefix, not just the best one.

  Scenario: Setup topology and establish sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "2001:db8::1/64" on bridge "br0"
    And I create namespace "z2" with IP "2001:db8::2/64" on bridge "br0"
    And I create namespace "z3" with IP "2001:db8::3/64" on bridge "br0"
    And I create namespace "z4" with IP "2001:db8::4/64" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "z4.yaml" to namespace "z4"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z3" to "2001:db8::1" should be "Established"
    And BGP session in "z3" to "2001:db8::2" should be "Established"
    And BGP session in "z3" to "2001:db8::4" should be "Established"
    And BGP session in "z4" to "2001:db8::3" should be "Established"

  Scenario: The AddPath receiver sees both paths for the prefix
    Given the test topology exists
    # z3 holds two candidate paths and, because z4 negotiated AddPath,
    # advertises BOTH — so z4's table shows the prefix twice, once per
    # originating AS. Without AddPath Send z4 would hold exactly the
    # single best path (one AS_PATH only).
    Then show command "show bgp ipv6 2001:db8:beef::/64" in namespace "z4" should eventually contain "65003 65001"
    And show command "show bgp ipv6 2001:db8:beef::/64" in namespace "z4" should eventually contain "65003 65002"

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
