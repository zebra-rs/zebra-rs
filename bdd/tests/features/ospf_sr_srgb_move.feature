@ospf_sr_srgb_move
@ospf
Feature: OSPFv2 and OSPFv3 keep a moved Prefix-SID's old label forwarding for a while
  As a network operator
  I want a Prefix-SID that an SRGB change moves to a new label to keep
  its old label forwarding for a while, on every router and in both
  OSPF versions, so that a neighbour still sending the old label (it has
  not processed the new advertisement yet) is not dropped
  (docs/design/mpls-label-allocation.md §6.1).

  A Prefix-SID's label is its originator's SRGB start plus the index.
  The chain runs OSPFv2 over IPv4 and OSPFv3 over IPv6, both with
  SR-MPLS. r3 moves its SRGB from 16000 to 18000: its OSPFv2 index 3
  moves from label 16003 to 18003 and its OSPFv3 index 13 from 16013 to
  18013, on r3 and on the routers forwarding toward it. Each installs
  the new label at once and keeps the old one for the hold, 60 s.

  Test Topology:
  ```
   r1 ──────────── r2 ──────────── r3
     10.0.12.0/24     10.0.23.0/24
     2001:db8:12::/64 2001:db8:23::/64
   lo 10.0.0.1/2/3 (OSPFv2 SID index 1/2/3)
      2001:db8::1/2/3 (OSPFv3 SID index 11/12/13)
  ```

  Scenario: Build the dual-stack chain on the default SRGB
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
    And ping from "r1" to "2001:db8::3" should eventually succeed
    And show command "show mpls ilm" in namespace "r1" should eventually contain "16003"
    And show command "show mpls ilm" in namespace "r1" should eventually contain "16013"
    And show command "show mpls ilm" in namespace "r3" should eventually contain "16003"
    And show command "show mpls ilm" in namespace "r3" should eventually contain "16013"

  Scenario: The moved Prefix-SIDs' old labels forward for the hold, then go
    Given the test topology exists
    When I apply config "r3-srgb.yaml" to namespace "r3"
    Then show command "show mpls ilm" in namespace "r1" should eventually contain "18003"
    And show command "show mpls ilm" in namespace "r1" should eventually contain "18013"
    And show command "show mpls ilm" in namespace "r3" should eventually contain "18003"
    And show command "show mpls ilm" in namespace "r3" should eventually contain "18013"
    # Each router has moved, and still forwards the old labels.
    And show command "show mpls ilm" in namespace "r1" should contain "16003"
    And show command "show mpls ilm" in namespace "r1" should contain "16013"
    And show command "show mpls ilm" in namespace "r3" should contain "16003"
    And show command "show mpls ilm" in namespace "r3" should contain "16013"
    # The hold runs out 60 s after each router moved.
    And show command "show mpls ilm" in namespace "r1" should not contain "16003" within 90 seconds
    And show command "show mpls ilm" in namespace "r1" should not contain "16013" within 30 seconds
    And show command "show mpls ilm" in namespace "r3" should not contain "16003" within 30 seconds
    And show command "show mpls ilm" in namespace "r3" should not contain "16013" within 30 seconds
    And show command "show mpls ilm" in namespace "r1" should contain "18003"
    And show command "show mpls ilm" in namespace "r1" should contain "18013"
    And ping from "r1" to "10.0.0.3" should succeed
    And ping from "r1" to "2001:db8::3" should succeed

  Scenario: Teardown
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I stop zebra-rs in namespace "r3"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    Then the test environment should be clean
