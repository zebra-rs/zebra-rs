@serial
@ospfv2_virtual_link
Feature: OSPFv2 virtual links connect a remote ABR to the backbone
  As a network operator
  I want `area <transit-id> virtual-link <router-id>` (RFC 2328 §15)
  to form a logical backbone adjacency between two ABRs across a
  non-backbone transit area — so an area with no physical backbone
  connection (area 2 below) still exchanges inter-area routes with
  area 0.

  Test Topology:
  ```
     area 0        area 0.0.0.1 (transit)      area 0.0.0.2
    lo 10.0.0.1   r1 -- 10.0.12.0/30 -- r2 -- 10.0.23.0/30 -- r3
                   \____ virtual-link ____/     lo 10.0.0.3
    r2 has NO physical area-0 interface; without the VL, r2 is not
    backbone-attached and area 2 never learns 10.0.0.1/32.
  ```

  Scenario: Virtual link forms and carries inter-area routes end to end
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I connect namespace "r1" interface "ethb" to namespace "r2" interface "etha"
    And I connect namespace "r2" interface "ethc" to namespace "r3" interface "ethb"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    And I wait 40 seconds

    # Physical adjacencies in the transit area and area 2.
    Then show command "show ospf neighbor" in namespace "r1" should contain "Full"
    And show command "show ospf neighbor" in namespace "r3" should contain "Full"

    # The virtual link itself: both endpoints carry a VLINK interface
    # whose neighbor reached Full (the VL runs in area 0.0.0.0).
    And show command "show ospf interface" in namespace "r1" should contain "VLINK"
    And show command "show ospf interface" in namespace "r2" should contain "VLINK"

    # Backbone reachability through the VL: r2 (no physical area-0
    # interface) learns r1's area-0 loopback...
    And show command "show ospf route" in namespace "r2" should contain "10.0.0.1/32"
    # ...and re-advertises area-2 destinations into the backbone, so
    # r1 reaches r3's loopback across the VL.
    And show command "show ospf route" in namespace "r1" should contain "10.0.0.3/32"

    # End to end: the area-2 internal router reaches the area-0
    # prefix — impossible without the virtual link.
    And show command "show ospf route" in namespace "r3" should contain "10.0.0.1/32"
    And ping from "r3" to "10.0.0.1" should succeed
    And ping from "r1" to "10.0.0.3" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    Then the test environment should be clean
