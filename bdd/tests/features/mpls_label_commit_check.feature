@mpls_label_commit_check
Feature: MPLS label checks at commit
  As a network operator
  I want a commit refused when it would put an MPLS label where another
  user of the label table already is, or where the dynamic allocators hand
  labels out
  So that the label table never holds a collision for me to clear later
  (docs/design/mpls-label-allocation.md §7)

  Test Topology:
  ```
  ┌───────────────┐
  │      br0      │
  └───────┬───────┘
          │
     ┌────┴────┐
     │   z1    │  OSPFv2 SR-MPLS
     │192.168. │  SRGB 16000-23999, SRLB 15000-15999
     │  0.1/24 │  lo Prefix-SID index 100
     └─────────┘  vz1ns Adjacency-SID absolute 15000
                  static mpls label 100
  ```

  Each refused command must leave the running config as it was, so every
  scenario closes on the running config: a positive control (a command
  that breaks nothing, rendered in the same form) shows the "not contain"
  checks cannot pass vacuously.

  Scenario: Setup topology
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply command "set router static mpls label 100 nexthop 192.168.0.2" in namespace "z1"
    Then show command "show running-config formal" in namespace "z1" should contain "router static mpls label 100 nexthop 192.168.0.2"
    And show command "show running-config formal" in namespace "z1" should contain "interface vz1ns adjacency-sid absolute 15000"

  Scenario: A static binding stays out of the SR blocks and the dynamic range
    Given the test topology exists
    Then applying command "set router static mpls label 24000 nexthop 192.168.0.2" in namespace "z1" should be rejected with "static MPLS label 24000 is in the dynamic label range (24000-1048574)"
    And applying command "set router static mpls label 16005 nexthop 192.168.0.2" in namespace "z1" should be rejected with "static MPLS label 16005 is in the SRGB of segment-routing block default (16000-23999)"
    And applying command "set router static mpls label 15005 nexthop 192.168.0.2" in namespace "z1" should be rejected with "static MPLS label 15005 is in the SRLB of segment-routing block default (15000-15999)"
    When I apply command "set router static mpls label 200 nexthop 192.168.0.2" in namespace "z1"
    Then show command "show running-config formal" in namespace "z1" should contain "router static mpls label 200 nexthop 192.168.0.2"
    And show command "show running-config formal" in namespace "z1" should not contain "mpls label 24000"
    And show command "show running-config formal" in namespace "z1" should not contain "mpls label 16005"
    And show command "show running-config formal" in namespace "z1" should not contain "mpls label 15005"

  Scenario: A configured Adjacency-SID lies in the SRLB, on one interface
    Given the test topology exists
    Then applying command "set router ospf area 0.0.0.0 interface vz1ns adjacency-sid absolute 16000" in namespace "z1" should be rejected with "OSPF area 0.0.0.0 interface vz1ns adjacency-sid absolute 16000 is outside the SRLB (15000-15999)"
    And applying command "set router ospf area 0.0.0.0 interface lo adjacency-sid absolute 15000" in namespace "z1" should be rejected with "adjacency-sid absolute 15000 is configured more than once: OSPF area 0.0.0.0 interface lo, OSPF area 0.0.0.0 interface vz1ns"
    When I apply command "set router ospf area 0.0.0.0 interface lo adjacency-sid absolute 15001" in namespace "z1"
    Then show command "show running-config formal" in namespace "z1" should contain "interface lo adjacency-sid absolute 15001"
    And show command "show running-config formal" in namespace "z1" should contain "interface vz1ns adjacency-sid absolute 15000"
    And show command "show running-config formal" in namespace "z1" should not contain "adjacency-sid absolute 16000"
    And show command "show running-config formal" in namespace "z1" should not contain "interface lo adjacency-sid absolute 15000"

  Scenario: A block change that breaks a configured label is refused
    Given the test topology exists
    # The SRLB moved over the static bindings, and away from both
    # Adjacency-SIDs.
    Then applying command "set segment-routing block default local start 64" in namespace "z1" should be rejected with "static MPLS label 100 is in the SRLB of segment-routing block default (64-1063)"
    # Too small an SRGB for lo's Prefix-SID index.
    And applying command "set segment-routing block default global range 50" in namespace "z1" should be rejected with "OSPF area 0.0.0.0 interface lo prefix-sid index 100 does not fit the SRGB (16000-16049, 50 labels)"
    And applying command "set segment-routing block default global start 1048570" in namespace "z1" should be rejected with "segment-routing block default global (1048570-1056569) is outside the label space (16-1048574)"
    And applying command "set segment-routing block default local start 16500" in namespace "z1" should be rejected with "segment-routing block default: its SRGB and SRLB overlap"
    When I apply command "set segment-routing block default global range 4000" in namespace "z1"
    Then show command "show running-config formal" in namespace "z1" should contain "segment-routing block default global range 4000"
    And show command "show running-config formal" in namespace "z1" should contain "segment-routing block default local start 15000"
    And show command "show running-config formal" in namespace "z1" should contain "segment-routing block default global start 16000"
    And show command "show running-config formal" in namespace "z1" should not contain "global range 50"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete bridge "br0"
    Then the test environment should be clean
