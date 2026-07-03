@serial
@ospfv2_redistribute_static
Feature: OSPFv2 instance-level redistribute static originates Type-5 AS-External LSAs
  As a network operator
  I want `router ospf redistribute static` to originate a Type-5
  AS-External LSA for every static route in the RIB — with the E-bit
  set in the Router-LSA so the domain computes paths to the ASBR — so
  that statically routed prefixes are reachable OSPF-wide without
  per-area configuration.

  Two routers on a point-to-point link. b carries a static route and
  redistributes it; a must install the prefix as an external route.

  Test Topology:
  ```
    a (10.0.0.1) -- 10.0.12.0/30 -- b (ASBR, 10.0.0.2)
                                    static 192.168.50.0/24 -> 10.0.12.1
                                    redistribute static -> Type-5

    on router X the interface toward router Y is named "ethY".
    loopbacks: a .1  b .2  (10.0.0.X/32).
  ```

  The static route's nexthop deliberately points back across the OSPF
  link (it resolves via the connected /30), so the route is installed
  in b's RIB and delivered to OSPF through the RIB redistribution
  subscription — the same path any real static route takes.

  Scenario: Static route appears as an external route on the neighbor
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    # Hello/DBD exchange, Type-5 origination and flood, SPF.
    And I wait 30 seconds

    Then show command "show ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ospf neighbor" in namespace "b" should contain "Full"
    # The redistributed prefix arrives as an AS-External route with the
    # default metric 20 (E2: metric is flat regardless of distance).
    And show command "show ospf route" in namespace "a" should contain "192.168.50.0/24"
    And show command "show ospf route" in namespace "a" should contain "[20]"
    # b itself must not self-install its own external.
    And show command "show ospf route" in namespace "b" should not contain "192.168.50.0/24"

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean
