@serial
@ospfv3_area_range
Feature: OSPFv3 area ranges aggregate Inter-Area-Prefix-LSAs at the ABR
  As a network operator
  I want `area <id> range <prefix>` on an OSPFv3 ABR to fold that
  area's intra-area routes into one aggregate Inter-Area-Prefix-LSA
  (RFC 2328 §12.4.3 over the RFC 5340 LSA model) — or hide the whole
  range with `not-advertise` — mirroring ospfv2_area_range.

  Test Topology (v6 mirror of ospfv2_area_range):
  ```
       area 0.0.0.1                            area 0.0.0.0
    b -- 2001:db8:12::/64 -- a (ABR) -- 2001:db8:13::/64 -- c
    r1 2001:db8:1:1::/64  <- inside the   area 0.0.0.1
    r2 2001:db8:1:2::/64  <- 2001:db8:1::/48 range
    lo 2001:db8::2/128    <- outside the range
  ```

  Scenario: Components fold into one aggregate; prefixes outside the range still advertise
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I connect namespace "a" interface "ethc" to namespace "c" interface "etha"
    And I create dummy interface "r1" with address "2001:db8:1:1::1/64" in namespace "b"
    And I create dummy interface "r2" with address "2001:db8:1:2::1/64" in namespace "b"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "c"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "c.yaml" to namespace "c"
    And I wait 40 seconds

    Then show command "show ospfv3 neighbor" in namespace "a" should contain "Full"
    And show command "show ospfv3 neighbor" in namespace "c" should contain "Full"
    # The aggregate at largest-component metric 20 + c's link 10.
    And show command "show ospfv3 route" in namespace "c" should contain "2001:db8:1::/48 metric 30"
    # The components must NOT leak individually.
    And show command "show ospfv3 route" in namespace "c" should not contain "2001:db8:1:1::/64"
    And show command "show ospfv3 route" in namespace "c" should not contain "2001:db8:1:2::/64"
    # Outside the range: still summarized individually.
    And show command "show ospfv3 route" in namespace "c" should contain "2001:db8::2/128"
    # Traffic to a component follows the aggregate end to end.
    And ping from "c" to "2001:db8:1:1::1" should succeed

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
    And I create dummy interface "r1" with address "2001:db8:1:1::1/64" in namespace "b"
    And I create dummy interface "r2" with address "2001:db8:1:2::1/64" in namespace "b"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "c"
    And I apply config "a_na.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "c.yaml" to namespace "c"
    And I wait 40 seconds

    Then show command "show ospfv3 neighbor" in namespace "c" should contain "Full"
    And show command "show ospfv3 route" in namespace "c" should not contain "2001:db8:1::/48"
    And show command "show ospfv3 route" in namespace "c" should not contain "2001:db8:1:1::/64"
    And show command "show ospfv3 route" in namespace "c" should not contain "2001:db8:1:2::/64"
    And show command "show ospfv3 route" in namespace "c" should contain "2001:db8::2/128"

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "c"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "c"
    Then the test environment should be clean
