@mpls_label_range
Feature: A configurable dynamic label range
  As a network operator
  I want to choose where dynamic labels (BGP's label chunks) come from with
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
     │   z1    │  BGP with one VRF: the VRF's label makes BGP take
     │192.168. │  a 128-label chunk at once
     │  0.1/24 │
     └─────────┘
  ```

  A change applies to chunks handed out from then on. A chunk BGP already
  holds stays where it is, outside the new range, until BGP gives it back;
  `show mpls label range` then counts it in the static region, and no
  static binding may take its labels.

  Scenario: The VRF takes its label from a chunk of the default range
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"
    Then show command "show mpls label table" in namespace "z1" should eventually contain "24000-24127    bgp     block           held"
    And show command "show mpls label range" in namespace "z1" should contain "24000-1048574    dynamic                                  128 labels in 1 block"
    # The VRF's decap ILM sits at the chunk's first label, in the text and
    # the JSON (which used to leave decap entries out).
    And show command "show mpls ilm" in namespace "z1" should eventually contain "24000  Pop         VPN Decap"
    And mpls ilm in namespace "z1" should contain label 24000

  Scenario: Moving the range leaves BGP's chunk where it is
    Given the test topology exists
    When I apply command "set mpls label-range dynamic start 30000" in namespace "z1"
    Then show command "show mpls label range" in namespace "z1" should eventually contain "30000-1048574    dynamic"
    And show command "show mpls label range" in namespace "z1" should contain "24000-29999      static                                   128 labels in 1 block"
    And show command "show mpls label table" in namespace "z1" should contain "24000-24127    bgp     block           held"

  Scenario: A static binding stays out of the range and of BGP's chunk
    Given the test topology exists
    Then applying command "set router static mpls label 35000 nexthop 192.168.0.2" in namespace "z1" should be rejected with "static MPLS label 35000 is in the dynamic label range (30000-1048574)"
    And applying command "set router static mpls label 24050 nexthop 192.168.0.2" in namespace "z1" should be rejected with "static MPLS label 24050 is in a label block bgp holds (24000-24127)"
    And applying command "set mpls label-range dynamic end 20000" in namespace "z1" should be rejected with "mpls label-range dynamic 30000-20000 is empty"
    When I apply command "set router static mpls label 29000 nexthop 192.168.0.2" in namespace "z1"
    Then show command "show running-config formal" in namespace "z1" should contain "router static mpls label 29000 nexthop 192.168.0.2"
    And show command "show running-config formal" in namespace "z1" should not contain "mpls label 35000"
    And show command "show running-config formal" in namespace "z1" should not contain "mpls label 24050"
    And show command "show mpls label range" in namespace "z1" should contain "30000-1048574    dynamic"

  Scenario: BGP's next chunk comes from the moved range
    Given the test topology exists
    When I apply command "delete router bgp" in namespace "z1"
    Then show command "show mpls label table" in namespace "z1" should eventually not contain "bgp"
    When I apply config "z1-range.yaml" to namespace "z1"
    Then show command "show mpls label table" in namespace "z1" should eventually contain "30000-30127    bgp     block           held"
    And show command "show mpls label range" in namespace "z1" should contain "30000-1048574    dynamic                                  128 labels in 1 block"
    And show command "show mpls label range" in namespace "z1" should not contain "static                                   128 labels"
    And show command "show mpls ilm" in namespace "z1" should eventually contain "30000  Pop         VPN Decap"
    And show command "show mpls ilm" in namespace "z1" should not contain "24000  Pop"
    And mpls ilm in namespace "z1" should contain label 30000
    And mpls ilm in namespace "z1" should not contain label 24000

  Scenario: A VRF the range has no room for gets its label once it grows
    Given the test topology exists
    When I apply command "delete router bgp" in namespace "z1"
    Then show command "show mpls label table" in namespace "z1" should eventually not contain "bgp"
    # 100 labels: no room for a 128-label chunk, so the VRF spawns
    # without a label, and with no decap ILM.
    When I apply config "z1-small.yaml" to namespace "z1"
    Then show command "show mpls label range" in namespace "z1" should eventually contain "30000-30099      dynamic"
    When I wait 5 seconds for BGP to operate
    Then show command "show mpls label table" in namespace "z1" should not contain "bgp"
    And show command "show mpls ilm" in namespace "z1" should not contain "VPN Decap"
    And mpls ilm in namespace "z1" should be empty
    # Growing the range is room returning: the VRF is relabelled, and
    # installs its decap ILM.
    When I apply command "set mpls label-range dynamic end 39999" in namespace "z1"
    Then show command "show mpls label table" in namespace "z1" should eventually contain "30000-30127    bgp     block           held"
    And show command "show mpls ilm" in namespace "z1" should eventually contain "30000  Pop         VPN Decap"
    And mpls ilm in namespace "z1" should contain label 30000

  Scenario: Deleting the VRF gives its label and the chunk back
    Given the test topology exists
    When I apply command "delete router bgp vrf vrf-a" in namespace "z1"
    # Its only label free, the chunk goes back to the RIB; BGP, still
    # running with its vpnv4 neighbor, holds no label.
    Then show command "show mpls label table" in namespace "z1" should eventually not contain "bgp"
    And show command "show mpls ilm" in namespace "z1" should not contain "VPN Decap"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete bridge "br0"
    Then the test environment should be clean
