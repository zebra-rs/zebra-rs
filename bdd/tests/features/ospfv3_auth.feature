@serial
@ospfv3_auth
Feature: OSPFv3 native authentication config drives the RFC 7166 trailer
  As a network operator
  I want `router ospfv3 area <id> interface <n> authentication
  message-digest` with `crypto-key` / `key-chain` to configure the
  RFC 7166 Authentication Trailer natively — no `router ospf` block
  required in an IPv6-only deployment — so adjacencies form only
  between routers sharing the key.

  Two routers on a point-to-point link; each scenario brings the
  pair up under one keying mode. The final scenario proves the
  negative: same SA-ID, different secrets, no neighbor ever forms.

  Test Topology:
  ```
    a (10.0.0.1) -- 2001:db8:12::/64 -- b (10.0.0.2)
  ```

  Scenario: HMAC-SHA-256 trailer via native crypto-key forms a Full adjacency
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a_sha256.yaml" to namespace "a"
    And I apply config "b_sha256.yaml" to namespace "b"
    And I wait 30 seconds

    Then show command "show ospfv3 neighbor" in namespace "a" should contain "Full"
    And show command "show ospfv3 neighbor" in namespace "a" should contain "10.0.0.2"
    And show command "show ospfv3 neighbor" in namespace "b" should contain "Full"
    And ping from "a" to "2001:db8::2" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean

  Scenario: RFC 8177 key-chain supplies the trailer key
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a_chain.yaml" to namespace "a"
    And I apply config "b_chain.yaml" to namespace "b"
    And I wait 30 seconds

    Then show command "show ospfv3 neighbor" in namespace "a" should contain "Full"
    And show command "show ospfv3 neighbor" in namespace "a" should contain "10.0.0.2"
    And show command "show ospfv3 neighbor" in namespace "b" should contain "Full"
    And ping from "a" to "2001:db8::2" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean

  Scenario: Mismatched trailer secrets never form a neighbor
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a_sha256.yaml" to namespace "a"
    And I apply config "b_badkey.yaml" to namespace "b"
    # Three hello cycles — plenty for a neighbor to appear if the
    # trailer verification (wrongly) let packets through.
    And I wait 30 seconds

    Then show command "show ospfv3 neighbor" in namespace "a" should not contain "10.0.0.2"
    And show command "show ospfv3 neighbor" in namespace "b" should not contain "10.0.0.1"

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean
