@serial
@bgp_ebgp_multihop
Feature: BGP eBGP multihop TTL (RFC 4271)
  As a network operator
  I want to configure `ebgp-multihop` on an eBGP neighbor so that a peer
  more than one hop away can be reached, and confirm the option is
  accepted end-to-end and does not break a session.

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
  ```

  Config files:
  - z1-1.yaml: AS 65001, neighbor 192.168.0.2 with `ebgp-multihop 5`.
  - z2-1.yaml: AS 65002, neighbor 192.168.0.1 with `ebgp-multihop 5`.

  Scope note: a genuine multi-hop test (peer behind a router, where the
  default eBGP TTL of 1 would be dropped and `ebgp-multihop` is required)
  needs a forwarding middle node, which the bridge-based harness cannot
  build. This scenario validates the YANG/dispatch path (`ebgp-multihop:
  5` is parsed and applied) and that raising the egress TTL to 5 does not
  break a directly-connected session. The default-TTL-1 directly-
  connected case is covered by @bgp_basic_ebgp, and the egress-TTL
  resolution itself is unit-tested (`session_ttl`).

  Scenario: A directly-connected eBGP session establishes with ebgp-multihop set
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
