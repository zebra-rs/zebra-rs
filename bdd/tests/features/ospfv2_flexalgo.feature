@ospfv2_flexalgo
Feature: OSPFv2 Flex-Algo computes with the winning definition
  Every router configured for a Flexible Algorithm computes it with the
  winning definition (RFC 9350 §5.3): the highest priority advertised in
  the area, then the highest Router ID. It never computes with its own
  configuration, which another router may not share. A router that cannot
  support the winner stops participating.

    r1 ===blue=== r2        r1 advertises 128: priority 100, exclude red
    |              |        r2 advertises 128: priority 200, exclude blue
    r4 --------- r3         r3, r4 participate without a definition

  All links cost 10. The r1-r2 link is blue at both ends; nothing is red.
  Computed with r2's definition, algorithm 128 avoids r1-r2, so r1 reaches
  r2 through r4 and r3. Computed with r1's own, it would go direct, via
  192.168.90.2.

  Config files: r1.yaml  r2.yaml  r3.yaml  r4.yaml

  Scenario: Build the ring
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I create namespace "r4"
    And I connect namespace "r1" interface "r1-r2" to namespace "r2" interface "r2-r1"
    And I connect namespace "r2" interface "r2-r3" to namespace "r3" interface "r3-r2"
    And I connect namespace "r3" interface "r3-r4" to namespace "r4" interface "r4-r3"
    And I connect namespace "r4" interface "r4-r1" to namespace "r1" interface "r1-r4"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I start zebra-rs in namespace "r4"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    And I apply config "r4.yaml" to namespace "r4"
    And I wait 10 seconds
    Then ping from "r1" to "192.168.90.2" should succeed
    And ping from "r1" to "192.168.90.13" should succeed

  Scenario: Every router computes with the higher-priority definition
    Given the test topology exists
    Then show command "show ospf flex-algo" in namespace "r3" should eventually contain "Area 0.0.0.0: definition from 10.0.0.2, priority 200; participating"
    And show command "show ospf flex-algo" in namespace "r4" should eventually contain "Area 0.0.0.0: definition from 10.0.0.2, priority 200; participating"
    And show command "show ospf flex-algo" in namespace "r2" should eventually contain "Area 0.0.0.0: definition from 10.0.0.2, this router, priority 200; participating"
    And show command "show ospf flex-algo" in namespace "r1" should eventually contain "Area 0.0.0.0: definition from 10.0.0.2, priority 200; participating"
    # r1 computes with r2's definition, not its own: no algorithm-128
    # route of r1's uses the blue link, and r2 is reached through r4.
    And show command "show ospf flex-algo" in namespace "r1" should eventually contain "via 192.168.90.13"
    And show command "show ospf flex-algo" in namespace "r1" should eventually not contain "via 192.168.90.2"
    # Participation is announced in each router's SR-Algorithm list.
    And show command "show ospf segment-routing" in namespace "r1" should eventually contain "SR-Node: 10.0.0.3"
    And show command "show ospf segment-routing" in namespace "r1" should contain "Algo.(s): SPF, FlexAlgo(128)"

  Scenario: A definition edit takes effect at once
    Given the test topology exists
    # Lowering r2's priority makes r1's definition the winner, which
    # excludes nothing present, so r1 reaches r2 directly again. A FAD
    # edit used to wait for an unrelated event to reach the wire.
    When I apply command "set router ospf flex-algo 128 priority 50" in namespace "r2"
    Then show command "show ospf flex-algo" in namespace "r3" should eventually contain "Area 0.0.0.0: definition from 10.0.0.1, priority 100; participating"
    And show command "show ospf flex-algo" in namespace "r1" should eventually contain "Area 0.0.0.0: definition from 10.0.0.1, this router, priority 100; participating"
    And show command "show ospf flex-algo" in namespace "r1" should eventually contain "via 192.168.90.2"

  Scenario: An unsupported winning definition stops participation everywhere
    Given the test topology exists
    # The M flag asks for the Flex-Algorithm prefix metric, which zebra-rs
    # does not implement, so no router can support the winner.
    When I apply command "set router ospf flex-algo 128 prefix-metric true" in namespace "r1"
    Then show command "show ospf flex-algo" in namespace "r3" should eventually contain "Area 0.0.0.0: definition from 10.0.0.1, priority 100; not participating: unsupported flag: prefix metric (M)"
    And show command "show ospf flex-algo" in namespace "r1" should eventually contain "not participating: unsupported flag: prefix metric (M)"
    And show command "show ospf flex-algo" in namespace "r1" should eventually not contain "via 192.168.90."
    # "It MUST NOT announce participation": no router's SR-Algorithm list
    # carries the algorithm any more.
    And show command "show ospf segment-routing" in namespace "r1" should eventually not contain "FlexAlgo(128)"
    # Clearing the flag restores participation and the routes.
    When I apply command "set router ospf flex-algo 128 prefix-metric false" in namespace "r1"
    Then show command "show ospf flex-algo" in namespace "r3" should eventually contain "Area 0.0.0.0: definition from 10.0.0.1, priority 100; participating"
    And show command "show ospf flex-algo" in namespace "r1" should eventually contain "via 192.168.90.2"

  Scenario: With no definition advertised, no router participates
    Given the test topology exists
    When I apply command "set router ospf flex-algo 128 advertise-definition false" in namespace "r1"
    And I apply command "set router ospf flex-algo 128 advertise-definition false" in namespace "r2"
    Then show command "show ospf flex-algo" in namespace "r3" should eventually contain "Area 0.0.0.0: not participating: no definition advertised"
    And show command "show ospf flex-algo" in namespace "r1" should eventually contain "Area 0.0.0.0: not participating: no definition advertised"
    And show command "show ospf flex-algo" in namespace "r1" should eventually not contain "via 192.168.90."

  Scenario: Teardown
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I stop zebra-rs in namespace "r4"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    And I delete namespace "r4"
    Then the test environment should be clean
