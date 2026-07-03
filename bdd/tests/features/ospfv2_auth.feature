@serial
@ospfv2_auth
Feature: OSPFv2 per-interface authentication gates adjacency formation
  As a network operator
  I want zebra-rs to authenticate OSPFv2 packets per interface — simple
  password (RFC 2328 §D.3), keyed-MD5 (§D.4), HMAC-SHA (RFC 5709) and
  RFC 8177 key-chains — so that adjacencies form only between routers
  sharing the key, and packets with mismatched keys are dropped.

  Two routers on a point-to-point link; each scenario brings the pair
  up under one authentication mode and proves the adjacency reaches
  Full and the loopbacks route. The final scenario proves the negative:
  same mode, different secrets, no neighbor ever appears.

  Test Topology:
  ```
    a (10.0.0.1) -- 10.0.12.0/30 -- b (10.0.0.2)

    on router X the interface toward router Y is named "ethY".
    loopbacks: a .1  b .2  (10.0.0.X/32).
  ```

  Scenario: Simple-password authentication forms a Full adjacency
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a_simple.yaml" to namespace "a"
    And I apply config "b_simple.yaml" to namespace "b"
    # First Hello (<=10s) + DBD exchange + SPF/route install.
    And I wait 30 seconds

    Then show command "show ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ospf neighbor" in namespace "a" should contain "10.0.0.2"
    And show command "show ospf neighbor" in namespace "b" should contain "Full"
    And show command "show ospf neighbor" in namespace "b" should contain "10.0.0.1"
    And ping from "a" to "10.0.0.2" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean

  Scenario: Keyed-MD5 authentication forms a Full adjacency
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a_md5.yaml" to namespace "a"
    And I apply config "b_md5.yaml" to namespace "b"
    And I wait 30 seconds

    Then show command "show ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ospf neighbor" in namespace "a" should contain "10.0.0.2"
    And show command "show ospf neighbor" in namespace "b" should contain "Full"
    And ping from "a" to "10.0.0.2" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean

  Scenario: HMAC-SHA-256 cryptographic authentication forms a Full adjacency
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a_sha256.yaml" to namespace "a"
    And I apply config "b_sha256.yaml" to namespace "b"
    And I wait 30 seconds

    Then show command "show ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ospf neighbor" in namespace "a" should contain "10.0.0.2"
    And show command "show ospf neighbor" in namespace "b" should contain "Full"
    And ping from "a" to "10.0.0.2" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean

  Scenario: RFC 8177 key-chain authentication forms a Full adjacency
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a_chain.yaml" to namespace "a"
    And I apply config "b_chain.yaml" to namespace "b"
    And I wait 30 seconds

    Then show command "show ospf neighbor" in namespace "a" should contain "Full"
    And show command "show ospf neighbor" in namespace "a" should contain "10.0.0.2"
    And show command "show ospf neighbor" in namespace "b" should contain "Full"
    And ping from "a" to "10.0.0.2" should succeed

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean

  Scenario: Mismatched MD5 secrets never form a neighbor
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I connect namespace "a" interface "ethb" to namespace "b" interface "etha"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I apply config "a_md5.yaml" to namespace "a"
    # Same mode and key-id, different secret: every Hello fails digest
    # verification and is dropped before neighbor creation.
    And I apply config "b_md5_badkey.yaml" to namespace "b"
    # Three hello cycles — plenty for a neighbor to appear if auth were
    # (wrongly) letting packets through.
    And I wait 30 seconds

    Then show command "show ospf neighbor" in namespace "a" should not contain "10.0.0.2"
    And show command "show ospf neighbor" in namespace "b" should not contain "10.0.0.1"

    # Teardown.
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I delete namespace "a"
    And I delete namespace "b"
    Then the test environment should be clean
