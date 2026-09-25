@isis_parallel_links
Feature: IS-IS forwards each parallel link through its own interface
  Two routers joined by two point-to-point links: pa at metric 10 and pb
  at metric 100, in the base topology and in MT 2 (IPv6 unicast). Both
  links lead to the same neighbour, so their reach entries carry the same
  neighbour ID. The route to the far loopback must leave by the interface
  of the link SPF chose. Keyed by neighbour alone, every parallel edge
  took the last interface's identity: pb, created second, so SPF chose pa
  and the kernel route used pb.

    p1 (10.0.80.1) ==pa (10)== p2 (10.0.80.2)
                   ==pb (100)=

  Config files: p1.yaml  p2.yaml

  Scenario: Build two routers joined by two links
    Given a clean test environment
    When I create namespace "p1"
    And I create namespace "p2"
    And I connect namespace "p1" interface "p1-pa" to namespace "p2" interface "p2-pa"
    And I connect namespace "p1" interface "p1-pb" to namespace "p2" interface "p2-pb"
    And I start zebra-rs in namespace "p1"
    And I start zebra-rs in namespace "p2"
    And I apply config "p1.yaml" to namespace "p1"
    And I apply config "p2.yaml" to namespace "p2"
    And I wait 10 seconds
    Then ping from "p1" to "192.168.80.2" should succeed
    And ping from "p1" to "192.168.80.6" should succeed

  Scenario: The cheaper link carries the traffic, by its own interface
    Given the test topology exists
    Then kernel route "10.0.80.2" in namespace "p1" should eventually contain "dev p1-pa"
    And kernel route "10.0.80.2" in namespace "p1" should eventually not contain "dev p1-pb"
    And kernel route "2001:db8:80::2" in namespace "p1" should eventually contain "dev p1-pa"
    And kernel route "2001:db8:80::2" in namespace "p1" should eventually not contain "dev p1-pb"

  Scenario: Raising the cheaper link's metric moves the traffic to the other
    Given the test topology exists
    When I apply command "set router isis interface p1-pa metric 200" in namespace "p1"
    And I apply command "set router isis interface p1-pa multi-topology ipv6-unicast metric 200" in namespace "p1"
    Then kernel route "10.0.80.2" in namespace "p1" should eventually contain "dev p1-pb"
    And kernel route "10.0.80.2" in namespace "p1" should eventually not contain "dev p1-pa"
    And kernel route "2001:db8:80::2" in namespace "p1" should eventually contain "dev p1-pb"
    And kernel route "2001:db8:80::2" in namespace "p1" should eventually not contain "dev p1-pa"

  Scenario: Equal metrics share the load across both links
    Given the test topology exists
    When I apply command "set router isis interface p1-pa metric 100" in namespace "p1"
    And I apply command "set router isis interface p1-pa multi-topology ipv6-unicast metric 100" in namespace "p1"
    Then kernel route "10.0.80.2" in namespace "p1" should eventually contain "dev p1-pa"
    And kernel route "10.0.80.2" in namespace "p1" should eventually contain "dev p1-pb"
    And kernel route "2001:db8:80::2" in namespace "p1" should eventually contain "dev p1-pa"
    And kernel route "2001:db8:80::2" in namespace "p1" should eventually contain "dev p1-pb"

  Scenario: Teardown
    Given the test topology exists
    When I stop zebra-rs in namespace "p1"
    And I stop zebra-rs in namespace "p2"
    And I delete namespace "p1"
    And I delete namespace "p2"
    Then the test environment should be clean
