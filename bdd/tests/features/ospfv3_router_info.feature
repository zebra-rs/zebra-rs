@ospfv3_router_info
Feature: OSPFv3 advertises its Segment Routing capabilities in the Router Information LSA
  RFC 8666 §4 places a router's OSPFv3 SR capabilities — its SRGB, SRLB,
  SR algorithms and Flexible Algorithm Definitions — in the RFC 7770 Router
  Information LSA (LS type 0xA00C). zebra-rs sent them only on an
  E-Router-LSA, which no other implementation reads, so a standard router
  learned no SRGB from zebra-rs and installed none of its Prefix-SIDs. It
  now sends the Router Information LSA, and the former carrier alongside for
  zebra-rs routers from before. A neighbour reads a router's capabilities
  from its Router Information LSA whenever it sends one.

  r1 and r2 run SR-MPLS over one point-to-point link, with the default SRGB
  (16000). r1's loopback Prefix-SID is index 1 (label 16001), and r1 defines
  Flex-Algo 128.

  Config files: r1.yaml  r2.yaml

  Scenario: A neighbour receives the Router Information LSA and resolves labels from it
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I connect namespace "r1" interface "r1-r2" to namespace "r2" interface "r2-r1"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    Then show command "show ospfv3 neighbor" in namespace "r2" should eventually contain "Full"
    # r1's own Router Information LSA reaches r2 — originated before the
    # adjacency, it arrives only if the database summary lists it.
    And show command "show ospfv3 database" in namespace "r2" should eventually contain "Router-Info-LSA          0                1.1.1.1"
    And show command "show ospfv3 database detail" in namespace "r2" should eventually contain "Type: 0xa00c (Router-Info-LSA)"
    And show command "show ospfv3 database detail" in namespace "r2" should eventually contain "Router Capabilities:"
    And show command "show ospfv3 database detail" in namespace "r2" should eventually contain "Segment Routing Global Range TLV:"
    And show command "show ospfv3 database detail" in namespace "r2" should eventually contain "Algorithm 128: Flex-Algo 128"
    # r1's SRGB now comes from its Router Information LSA alone.
    And show command "show ospfv3 segment-routing" in namespace "r2" should eventually contain "SR-Node: 1.1.1.1    Area: 0.0.0.0    SRGB: [16000/18000]"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "16001"

  Scenario: Teardown
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    Then the test environment should be clean
