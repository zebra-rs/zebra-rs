@isis_flexalgo_delay
Feature: IS-IS Flex-Algo on link delay costs every link as it is advertised
  A Flexible Algorithm with metric-type 1 routes on each link's minimum
  unidirectional delay, from the Min/Max Link Delay sub-TLV the link
  advertises; a link advertising no delay is pruned (RFC 9350 §15). Every
  router computing the algorithm must build the same topology, so this
  router costs its own links from what it advertises too, not from its
  interface configuration. A Min delay configured without a Max is not
  advertised — the sub-TLV needs both — so every router, this one
  included, prunes that link.

    ce (10.0.0.1) ---- n1 (10.0.0.2)     delay ce->n1: Min 100, no Max
        \             /                  ce->n2 300, n2->n1 100
         n2 (10.0.0.3)                   (all in microseconds)

  ce advertises algorithm 128 on delay. ce's link to n1 advertises no
  delay, so algorithm 128 reaches n1 from ce through n2, at 300 + 100 (and
  n1's loopback prefix metric, 10). Costing the link from its configured
  Min, ce went direct at 100, a path no other router computed.

  Config files: ce.yaml  n1.yaml  n2.yaml

  Scenario: Build the triangle
    Given a clean test environment
    When I create namespace "ce"
    And I create namespace "n1"
    And I create namespace "n2"
    And I connect namespace "ce" interface "ce-n1" to namespace "n1" interface "n1-ce"
    And I connect namespace "ce" interface "ce-n2" to namespace "n2" interface "n2-ce"
    And I connect namespace "n2" interface "n2-n1" to namespace "n1" interface "n1-n2"
    And I start zebra-rs in namespace "ce"
    And I start zebra-rs in namespace "n1"
    And I start zebra-rs in namespace "n2"
    And I apply config "ce.yaml" to namespace "ce"
    And I apply config "n1.yaml" to namespace "n1"
    And I apply config "n2.yaml" to namespace "n2"
    And I wait 10 seconds
    Then ping from "ce" to "192.168.70.2" should succeed
    And show command "show isis flex-algo" in namespace "n1" should eventually contain "definition from ce (0000.0000.0001)"

  Scenario: A link advertised without a delay is pruned, by its own router too
    Given the test topology exists
    # Algorithm 128 reaches n1 through n2 (300 + 100, + 10 for the
    # prefix), not over the link whose delay ce does not advertise.
    Then show command "show isis flex-algo route algorithm 128" in namespace "ce" should eventually contain "10.0.0.2/32          410      192.168.70.6"
    And show command "show isis flex-algo route algorithm 128" in namespace "ce" should not contain "10.0.0.2/32          110"

  Scenario: Advertising the delay brings the link back
    Given the test topology exists
    When I apply command "set router isis interface ce-n1 te-metric max-delay 150" in namespace "ce"
    Then show command "show isis flex-algo route algorithm 128" in namespace "ce" should eventually contain "10.0.0.2/32          110      192.168.70.2"

  Scenario: Teardown
    Given the test topology exists
    When I stop zebra-rs in namespace "ce"
    And I stop zebra-rs in namespace "n1"
    And I stop zebra-rs in namespace "n2"
    And I delete namespace "ce"
    And I delete namespace "n1"
    And I delete namespace "n2"
    Then the test environment should be clean
