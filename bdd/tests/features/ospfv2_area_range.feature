@serial
@ospfv2_area_range
Feature: OSPFv2 area ranges aggregate Type-3 summaries at the ABR
  As a network operator
  I want `area <id> range <prefix>` on an ABR to fold that area's
  intra-area routes into one aggregate Type-3 (RFC 2328 §12.4.3) —
  or hide the whole range with `not-advertise` — so that backbone
  routers carry one summary instead of every component prefix.

  Test Topology:
  ```
       area 0.0.0.1                          area 0.0.0.0
    b (10.0.0.2) -- 10.0.12.0/30 -- a (ABR, 10.0.0.1) -- 10.0.13.0/30 -- c (10.0.0.3)
    r1 10.1.1.0/24  <- inside the      area 0.0.0.1
    r2 10.1.2.0/24  <- 10.1.0.0/16     range 10.1.0.0/16
    lo 10.0.0.2/32  <- outside the range

    on router X the interface toward router Y is named "ethY".
  ```

  b's dummy interfaces r1/r2 are OSPF-enabled stub prefixes inside
  the range; its loopback /32 is outside. Metric check: components
  cost 20 at the ABR (link 10 + stub 10), so the aggregate rides at
  the largest component metric 20 and lands on c at [30].

  Scenario: Components fold into one aggregate; prefixes outside the range still advertise
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I connect namespace "a" interface "ethc" to namespace "c" interface "etha"
    # Dummies must exist before the config applies so their OSPF
    # interface entries bind at enable time.
    And I create dummy interface "r1" with address "10.1.1.1/24" in namespace "b"
    And I create dummy interface "r2" with address "10.1.2.1/24" in namespace "b"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "c"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "c.yaml" to namespace "c"
    And I wait 40 seconds

    Then show command "show ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ospf neighbor" in namespace "c" should contain "Full"
    # The aggregate — at the largest component metric (20) + c's link (10).
    And show command "show ospf route" in namespace "c" should contain "10.1.0.0/16"
    And show command "show ospf route" in namespace "c" should contain "[30]"
    # The components must NOT leak individually.
    And show command "show ospf route" in namespace "c" should not contain "10.1.1.0/24"
    And show command "show ospf route" in namespace "c" should not contain "10.1.2.0/24"
    # Outside the range: still summarized individually.
    And show command "show ospf route" in namespace "c" should contain "10.0.0.2/32"
    # Traffic to a component follows the aggregate end to end.
    And ping from "c" to "10.1.1.1" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "c"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "c"
    Then the test environment should be clean

  Scenario: not-advertise hides the aggregate and the components
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I connect namespace "a" interface "ethc" to namespace "c" interface "etha"
    And I create dummy interface "r1" with address "10.1.1.1/24" in namespace "b"
    And I create dummy interface "r2" with address "10.1.2.1/24" in namespace "b"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "c"
    And I apply config "a_na.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "c.yaml" to namespace "c"
    And I wait 40 seconds

    Then show command "show ospf neighbor" in namespace "c" should contain "Full"
    # The whole range is hidden — no aggregate, no components.
    And show command "show ospf route" in namespace "c" should not contain "10.1.0.0/16"
    And show command "show ospf route" in namespace "c" should not contain "10.1.1.0/24"
    And show command "show ospf route" in namespace "c" should not contain "10.1.2.0/24"
    # Prefixes outside the range are unaffected.
    And show command "show ospf route" in namespace "c" should contain "10.0.0.2/32"

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "c"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "c"
    Then the test environment should be clean
