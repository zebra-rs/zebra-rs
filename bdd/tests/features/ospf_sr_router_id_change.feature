@serial
@ospf_sr_router_id_change
Feature: Segment Routing survives an OSPF Router-ID change
  Everything a router advertises is advertised under its Router-ID, so a
  Router-ID change flushes it all and must re-originate it under the new
  one. Segment Routing's LSAs were not re-originated: the SR capabilities
  (the SRGB peers resolve Prefix-SIDs against) and the Prefix-SID LSAs went
  with the flush, and every Prefix-SID of the router left the network until
  Segment Routing was toggled.

  Two point-to-point pairs, both running SR-MPLS with loopback Prefix-SIDs:
  a1-a2 on OSPFv3, b1-b2 on OSPFv2. a1 and b1 start as Router-ID 1.1.1.1
  and change to 9.9.9.9; a2 and b2 observe. The SRGB is the default,
  16000; a1's Prefix-SID is index 1 (label 16001), b1's index 11 (16011).

  Config files: a1.yaml  a2.yaml  b1.yaml  b2.yaml

  Scenario: Build both pairs and learn each other's Prefix-SIDs
    Given a clean test environment
    When I create namespace "a1"
    And I create namespace "a2"
    And I create namespace "b1"
    And I create namespace "b2"
    And I connect namespace "a1" interface "a1-a2" to namespace "a2" interface "a2-a1"
    And I connect namespace "b1" interface "b1-b2" to namespace "b2" interface "b2-b1"
    And I start zebra-rs in namespace "a1"
    And I start zebra-rs in namespace "a2"
    And I start zebra-rs in namespace "b1"
    And I start zebra-rs in namespace "b2"
    And I apply config "a1.yaml" to namespace "a1"
    And I apply config "a2.yaml" to namespace "a2"
    And I apply config "b1.yaml" to namespace "b1"
    And I apply config "b2.yaml" to namespace "b2"
    And I wait 15 seconds
    Then show command "show ospfv3 segment-routing" in namespace "a2" should eventually contain "SR-Node: 1.1.1.1    Area: 0.0.0.0    SRGB: [16000/23999]"
    And show command "show mpls ilm" in namespace "a2" should eventually contain "16001"
    And show command "show ospf segment-routing" in namespace "b2" should eventually contain "SR-Node: 1.1.1.1    SRGB: [16000/23999]"
    And show command "show mpls ilm" in namespace "b2" should eventually contain "16011"

  Scenario: OSPFv3 advertises its SR capabilities and Prefix-SID under the new Router-ID
    Given the test topology exists
    When I apply command "set router ospfv3 router-id 9.9.9.9" in namespace "a1"
    # The old identity's LSAs are flushed, so the Prefix-SID is learned
    # afresh — with its SRGB — under the new one.
    Then show command "show ospfv3 database" in namespace "a2" should eventually not contain "1.1.1.1"
    And show command "show ospfv3 segment-routing" in namespace "a2" should eventually contain "SR-Node: 9.9.9.9    Area: 0.0.0.0    SRGB: [16000/23999]"
    And show command "show mpls ilm" in namespace "a2" should eventually contain "16001"

  Scenario: OSPFv2 advertises its SR capabilities and Prefix-SID under the new Router-ID
    Given the test topology exists
    When I apply command "set router ospf router-id 9.9.9.9" in namespace "b1"
    Then show command "show ospf database" in namespace "b2" should eventually not contain "1.1.1.1"
    And show command "show ospf segment-routing" in namespace "b2" should eventually contain "SR-Node: 9.9.9.9    SRGB: [16000/23999]"
    And show command "show mpls ilm" in namespace "b2" should eventually contain "16011"

  Scenario: Teardown
    Given the test topology exists
    When I stop zebra-rs in namespace "a1"
    And I stop zebra-rs in namespace "a2"
    And I stop zebra-rs in namespace "b1"
    And I stop zebra-rs in namespace "b2"
    And I delete namespace "a1"
    And I delete namespace "a2"
    And I delete namespace "b1"
    And I delete namespace "b2"
    Then the test environment should be clean
