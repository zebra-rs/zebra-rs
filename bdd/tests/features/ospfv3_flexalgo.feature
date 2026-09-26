@ospfv3_flexalgo
Feature: OSPFv3 Flex-Algo computes with the winning definition
  Every router configured for a Flexible Algorithm computes it with the
  winning definition (RFC 9350 §5.3): the highest priority advertised in
  the area, then the highest Router ID. It never computes with its own
  configuration, which another router may not share. A router that cannot
  support the winner stops participating. The OSPFv3 twin of
  ospfv2_flexalgo; zebra-rs's OSPFv3 carries definitions and the
  SR-Algorithm list in its SR-info E-Router-LSA.

    r1 ===blue=== r2        r1 advertises 128: priority 100, exclude red
    |              |        r2 advertises 128: priority 200, exclude blue
    r4 --------- r3         r3, r4 participate without a definition

  All links cost 10. The r1-r2 link is blue at both ends; nothing is red.
  Computed with r2's definition, algorithm 128 avoids r1-r2, so r1 reaches
  r2 through r4 and r3, at cost 30. Computed with r1's own, it would go
  direct, at cost 10.

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
    Then ping from "r1" to "2001:db8::2" should eventually succeed
    And ping from "r1" to "2001:db8::3" should eventually succeed

  Scenario: Every router computes with the higher-priority definition
    Given the test topology exists
    Then show command "show ospfv3 flex-algo" in namespace "r3" should eventually contain "Area 0.0.0.0: definition from 10.0.0.2, priority 200; participating"
    And show command "show ospfv3 flex-algo" in namespace "r4" should eventually contain "Area 0.0.0.0: definition from 10.0.0.2, priority 200; participating"
    And show command "show ospfv3 flex-algo" in namespace "r2" should eventually contain "Area 0.0.0.0: definition from 10.0.0.2, this router, priority 200; participating"
    And show command "show ospfv3 flex-algo" in namespace "r1" should eventually contain "Area 0.0.0.0: definition from 10.0.0.2, priority 200; participating"
    # r1 computes with r2's definition, not its own: algorithm 128 does
    # not use the blue link, so r2 is reached through r4.
    And show command "show ospfv3 flex-algo" in namespace "r1" should eventually contain "10.0.0.2 cost 30 via 10.0.0.4"
    # Participation is announced in each router's SR-Algorithm list.
    And show command "show ospfv3 database detail" in namespace "r1" should eventually contain "Algorithm 128:"

  Scenario: A definition edit takes effect at once
    Given the test topology exists
    # Lowering r2's priority makes r1's definition the winner, which
    # excludes nothing present, so r1 reaches r2 directly again. A FAD
    # edit used to wait for an unrelated event to reach the wire.
    When I apply command "set router ospfv3 flex-algo 128 priority 50" in namespace "r2"
    Then show command "show ospfv3 flex-algo" in namespace "r3" should eventually contain "Area 0.0.0.0: definition from 10.0.0.1, priority 100; participating"
    And show command "show ospfv3 flex-algo" in namespace "r1" should eventually contain "Area 0.0.0.0: definition from 10.0.0.1, this router, priority 100; participating"
    And show command "show ospfv3 flex-algo" in namespace "r1" should eventually contain "10.0.0.2 cost 10 via 10.0.0.2"

  Scenario: An unsupported winning definition stops participation everywhere
    Given the test topology exists
    # The M flag asks for the Flex-Algorithm prefix metric, which zebra-rs
    # does not implement, so no router can support the winner.
    When I apply command "set router ospfv3 flex-algo 128 prefix-metric true" in namespace "r1"
    Then show command "show ospfv3 flex-algo" in namespace "r3" should eventually contain "Area 0.0.0.0: definition from 10.0.0.1, priority 100; not participating: unsupported flag: prefix metric (M)"
    And show command "show ospfv3 flex-algo" in namespace "r1" should eventually contain "not participating: unsupported flag: prefix metric (M)"
    And show command "show ospfv3 flex-algo" in namespace "r1" should eventually not contain "10.0.0.2 cost"
    # "It MUST NOT announce participation": no router's SR-Algorithm list
    # carries the algorithm any more.
    And show command "show ospfv3 database detail" in namespace "r1" should eventually not contain "Algorithm 128:"
    # Clearing the flag restores participation and the routes.
    When I apply command "set router ospfv3 flex-algo 128 prefix-metric false" in namespace "r1"
    Then show command "show ospfv3 flex-algo" in namespace "r3" should eventually contain "Area 0.0.0.0: definition from 10.0.0.1, priority 100; participating"
    And show command "show ospfv3 flex-algo" in namespace "r1" should eventually contain "10.0.0.2 cost 10 via 10.0.0.2"

  Scenario: With no definition advertised, no router participates
    Given the test topology exists
    When I apply command "set router ospfv3 flex-algo 128 advertise-definition false" in namespace "r1"
    And I apply command "set router ospfv3 flex-algo 128 advertise-definition false" in namespace "r2"
    Then show command "show ospfv3 flex-algo" in namespace "r3" should eventually contain "Area 0.0.0.0: not participating: no definition advertised"
    And show command "show ospfv3 flex-algo" in namespace "r1" should eventually contain "Area 0.0.0.0: not participating: no definition advertised"
    And show command "show ospfv3 flex-algo" in namespace "r1" should eventually not contain "10.0.0.2 cost"

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
