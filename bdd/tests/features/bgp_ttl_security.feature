@serial
@bgp_ttl_security
Feature: BGP TTL Security / GTSM (RFC 5082)
  As a network operator
  I want to protect a directly-connected eBGP session with the
  Generalized TTL Security Mechanism (GTSM) so that only a peer one hop
  away — whose packets arrive with TTL 255 — can keep the session up.

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
  - z1-1.yaml: AS 65001, neighbor 192.168.0.2 WITH `ttl-security`.
  - z2-1.yaml: AS 65002, neighbor 192.168.0.1 WITHOUT `ttl-security`
    (asymmetric — z1 enforces GTSM, z2 does not).
  - z2-2.yaml: AS 65002, neighbor 192.168.0.1 WITH `ttl-security`
    (symmetric — both ends enforce GTSM).

  GTSM sends BGP at TTL 255 and the kernel drops any segment that
  arrives below 255 (IP_MINTTL). A Linux bridge does not decrement TTL,
  so the two scenarios isolate the two halves of the mechanism:

  - Asymmetric: z2 still sends at the default TTL (64). z1's minimum-TTL
    floor drops z2's OPEN, so the session cannot come up — this proves
    the ingress filter is active.
  - Symmetric: once z2 also pins egress to 255, z1 accepts its packets
    and the session establishes — this proves egress-255 is applied on
    both the active and the passive side, and that enabling the flag at
    runtime bounces the peer into a working session.

  Scenario: Asymmetric ttl-security keeps the session down
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should not be "Established"
    And BGP session in "z2" to "192.168.0.1" should not be "Established"

  Scenario: Enabling ttl-security on both ends establishes the session
    Given the test topology exists
    When I apply config "z2-2.yaml" to namespace "z2"
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
