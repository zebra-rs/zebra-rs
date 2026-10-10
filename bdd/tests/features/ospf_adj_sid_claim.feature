@ospf_adj_sid_claim
Feature: A configured OSPF Adjacency-SID takes its label from a dynamic holder
  As a network operator
  I want an absolute Adjacency-SID I configure to get the SRLB label I
  chose even when another protocol's dynamic Adjacency-SID holds it, so
  that the label I pick does not succeed or fail by the order in which
  adjacencies came up (docs/design/mpls-label-allocation.md §5.1).

  IS-IS, OSPFv2 and OSPFv3 draw their dynamic Adjacency-SIDs from one
  SRLB, 15000..15999, lowest label first. r1 starts with IS-IS only, so
  its IS-IS adjacency holds 15000. Then OSPFv2 comes up with
  `adjacency-sid absolute 15000` on the same link: IS-IS is told to let
  15000 go, takes another label, and once its forwarding entry at 15000
  is withdrawn, OSPFv2 advertises and installs 15000. In `show mpls ilm`
  an IS-IS entry reads `i 115` and an OSPF one `O 110`; `show mpls label
  table` and `show mpls label range` show who holds each SRLB label.

  Test Topology:
  ```
   r1 ──────────── r2
     10.0.12.0/30
   lo 192.168.1.1/2
  ```

  Scenario: IS-IS's adjacency holds the first SRLB label
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I connect namespace "r1" interface "r1-r2" to namespace "r2" interface "r2-r1"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1-isis.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    Then show command "show isis neighbor" in namespace "r1" should eventually contain "r2"
    And show command "show mpls ilm" in namespace "r1" should eventually contain "i 115  15000"
    And show command "show mpls label table" in namespace "r1" should contain "15000          isis    local           held"

  Scenario: OSPFv2's configured Adjacency-SID moves IS-IS off 15000
    Given the test topology exists
    When I apply config "r1-claim.yaml" to namespace "r1"
    Then show command "show ospf neighbor" in namespace "r1" should eventually contain "Full"
    And show command "show mpls ilm" in namespace "r1" should eventually contain "O 110  15000"
    And show command "show mpls ilm" in namespace "r1" should eventually not contain "i 115  15000"
    # IS-IS still has an Adjacency-SID, on another label.
    And show command "show mpls ilm" in namespace "r1" should contain "i 115  1500"
    And command "ip -f mpls route show" in namespace "r1" should eventually contain "15000"
    # The label table names the claim and IS-IS's label beside it. OSPFv2's
    # dynamic label for the adjacency, advertised while the claim waited,
    # goes back once the configured one is advertised: it would be neither
    # advertised nor installed. The range counts the two left.
    And show command "show mpls label table" in namespace "r1" should contain "15000          ospf    configured SID  claimed"
    And show command "show mpls label table" in namespace "r1" should contain "isis    local           held"
    And show command "show mpls label table" in namespace "r1" should eventually not contain "ospf    local"
    And show command "show mpls label table label 15000" in namespace "r1" should contain "Label 15000: SRLB of segment-routing block default"
    And show command "show mpls label table label 15000" in namespace "r1" should contain "15000          ospf    configured SID  claimed"
    And show command "show mpls label range" in namespace "r1" should eventually contain "15000-15999      SRLB of segment-routing block default    2 labels"

  Scenario: Dropping the configuration gives 15000 back
    Given the test topology exists
    When I apply config "r1-noclaim.yaml" to namespace "r1"
    Then show command "show mpls ilm" in namespace "r1" should eventually not contain "O 110  15000"
    # OSPFv2 falls back to a dynamic label.
    And show command "show mpls ilm" in namespace "r1" should eventually contain "O 110  1500"
    And show command "show mpls ilm" in namespace "r1" should contain "i 115  1500"
    And show command "show mpls label table" in namespace "r1" should eventually not contain "configured SID"
    And show command "show mpls label table" in namespace "r1" should contain "ospf    local           held"

  Scenario: Teardown
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    Then the test environment should be clean
