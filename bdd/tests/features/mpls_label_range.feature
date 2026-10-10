@mpls_label_range
Feature: A configurable dynamic label range
  As a network operator
  I want to choose where dynamic labels (BGP's label blocks) come from with
  `mpls label-range dynamic`, the labels it leaves being free for static
  bindings, and a change to it that never disturbs labels in use
  (docs/design/mpls-label-allocation.md §3, §7, §8)

  Test Topology:
  ```
  ┌───────────────┐
  │      br0      │
  └───────┬───────┘
          │
     ┌────┴────┐
     │   z1    │  BGP, a vpnv4 neighbor that never comes up:
     │192.168. │  vpnv4 makes BGP take a 1024-label block at once
     │  0.1/24 │
     └─────────┘
  ```

  A change applies to blocks handed out from then on. A block BGP already
  holds stays where it is, outside the new range, until BGP gives it back;
  `show mpls label range` then counts it in the static region, and no
  static binding may take its labels.

  Scenario: BGP takes a block from the default range
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"
    Then show command "show mpls label table" in namespace "z1" should eventually contain "24000-25023    bgp     block           held"
    And show command "show mpls label range" in namespace "z1" should contain "24000-1048574    dynamic                                  1024 labels in 1 block"

  Scenario: Moving the range leaves BGP's block where it is
    Given the test topology exists
    When I apply command "set mpls label-range dynamic start 30000" in namespace "z1"
    Then show command "show mpls label range" in namespace "z1" should eventually contain "30000-1048574    dynamic"
    And show command "show mpls label range" in namespace "z1" should contain "24000-29999      static                                   1024 labels in 1 block"
    And show command "show mpls label table" in namespace "z1" should contain "24000-25023    bgp     block           held"

  Scenario: A static binding stays out of the range and of BGP's block
    Given the test topology exists
    Then applying command "set router static mpls label 35000 nexthop 192.168.0.2" in namespace "z1" should be rejected with "static MPLS label 35000 is in the dynamic label range (30000-1048574)"
    And applying command "set router static mpls label 24500 nexthop 192.168.0.2" in namespace "z1" should be rejected with "static MPLS label 24500 is in a label block bgp holds (24000-25023)"
    And applying command "set mpls label-range dynamic end 20000" in namespace "z1" should be rejected with "mpls label-range dynamic 30000-20000 is empty"
    When I apply command "set router static mpls label 29000 nexthop 192.168.0.2" in namespace "z1"
    Then show command "show running-config formal" in namespace "z1" should contain "router static mpls label 29000 nexthop 192.168.0.2"
    And show command "show running-config formal" in namespace "z1" should not contain "mpls label 35000"
    And show command "show running-config formal" in namespace "z1" should not contain "mpls label 24500"
    And show command "show mpls label range" in namespace "z1" should contain "30000-1048574    dynamic"

  Scenario: BGP's next block comes from the moved range
    Given the test topology exists
    When I apply command "delete router bgp" in namespace "z1"
    Then show command "show mpls label table" in namespace "z1" should eventually not contain "bgp"
    When I apply config "z1-range.yaml" to namespace "z1"
    Then show command "show mpls label table" in namespace "z1" should eventually contain "30000-31023    bgp     block           held"
    And show command "show mpls label range" in namespace "z1" should contain "30000-1048574    dynamic                                  1024 labels in 1 block"
    And show command "show mpls label range" in namespace "z1" should not contain "static                                   1024 labels"

  Scenario: A block request the range has no room for waits until it grows
    Given the test topology exists
    When I apply command "delete router bgp" in namespace "z1"
    Then show command "show mpls label table" in namespace "z1" should eventually not contain "bgp"
    # 100 labels: BGP's 1024-label request finds no room and waits.
    When I apply config "z1-small.yaml" to namespace "z1"
    Then show command "show mpls label range" in namespace "z1" should eventually contain "30000-30099      dynamic"
    When I wait 5 seconds for BGP to operate
    Then show command "show mpls label table" in namespace "z1" should not contain "bgp"
    # Growing the range serves the waiting request: no new request comes,
    # BGP sends none while one is unanswered.
    When I apply command "set mpls label-range dynamic end 39999" in namespace "z1"
    Then show command "show mpls label table" in namespace "z1" should eventually contain "30000-31023    bgp     block           held"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete bridge "br0"
    Then the test environment should be clean
