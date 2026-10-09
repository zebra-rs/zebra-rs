@isis_sr_srgb_move
@isis
Feature: IS-IS keeps a moved Prefix-SID's old label forwarding for a while
  As a network operator
  I want a Prefix-SID that an SRGB change moves to a new label to keep
  its old label forwarding for a while, on every router, so that a
  neighbour still sending the old label (it has not processed the new
  advertisement yet) is not dropped
  (docs/design/mpls-label-allocation.md §6.1).

  A Prefix-SID's label is its originator's SRGB start plus the index.
  r3 moves its SRGB from 16000 to 18000, so its index 3 moves from label
  16003 to 18003: on r3 (its own pop entry), on r2 (the penultimate hop,
  a pop) and on r1 (a swap toward r2). Each installs 18003 at once and
  keeps 16003 for the hold, 60 s, then withdraws it.

  Test Topology:
  ```
   r1 ──────────── r2 ──────────── r3
     10.0.12.0/24     10.0.23.0/24
   lo 10.0.0.1/2/3, Prefix-SID index 1/2/3
  ```

  Scenario: Build the chain on the default SRGB
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I connect namespace "r1" interface "r1-r2" to namespace "r2" interface "r2-r1"
    And I connect namespace "r2" interface "r2-r3" to namespace "r3" interface "r3-r2"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I start zebra-rs in namespace "r3"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I apply config "r3.yaml" to namespace "r3"
    Then ping from "r1" to "10.0.0.3" should eventually succeed
    And show command "show mpls ilm" in namespace "r1" should eventually contain "16003"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "16003"
    And show command "show mpls ilm" in namespace "r3" should eventually contain "16003"

  Scenario: The moved Prefix-SID's old label forwards for the hold, then goes
    Given the test topology exists
    When I apply config "r3-srgb.yaml" to namespace "r3"
    Then show command "show mpls ilm" in namespace "r1" should eventually contain "18003"
    And show command "show mpls ilm" in namespace "r2" should eventually contain "18003"
    And show command "show mpls ilm" in namespace "r3" should eventually contain "18003"
    # Each router has moved, and still forwards the old label.
    And show command "show mpls ilm" in namespace "r1" should contain "16003"
    And show command "show mpls ilm" in namespace "r2" should contain "16003"
    And show command "show mpls ilm" in namespace "r3" should contain "16003"
    And command "ip -f mpls route show" in namespace "r1" should eventually contain "16003"
    And ping from "r1" to "10.0.0.3" should succeed
    # The hold runs out 60 s after each router moved.
    And show command "show mpls ilm" in namespace "r1" should not contain "16003" within 90 seconds
    And show command "show mpls ilm" in namespace "r2" should not contain "16003" within 30 seconds
    And show command "show mpls ilm" in namespace "r3" should not contain "16003" within 30 seconds
    And command "ip -f mpls route show" in namespace "r1" should eventually not contain "16003"
    And show command "show mpls ilm" in namespace "r1" should contain "18003"
    And ping from "r1" to "10.0.0.3" should succeed

  Scenario: Teardown
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    Then the test environment should be clean
