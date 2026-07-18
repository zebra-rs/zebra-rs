@serial
@bgp_as4
Feature: BGP 4-octet AS support (RFC 6793)
  As a network operator
  I want sessions with 4-byte-ASN routers to establish and carry real AS paths,
  including toward legacy 2-octet (OLD) speakers via AS_TRANS + AS4_PATH.

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS70000 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
  ```

  Config files:
  - z1-1.yaml: AS 70000 (4-byte), peer to 192.168.0.2, network 10.0.0.1/32
  - z2-1.yaml: AS 65002, peer to 192.168.0.1, network 10.1.0.1/32
  - z2-2.yaml: z2-1 plus `capability four-octet false` — z2 presents
    itself as an OLD (2-octet) speaker, so z1 must fall back to a
    2-octet AS_PATH with AS_TRANS plus the AS4_PATH attribute.

  AS 70000 renders as "1.4464" in asdot notation (RFC 5396).

  Scenario: A 4-byte-ASN neighbor establishes via AS_TRANS + AS4 capability
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.0.2/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"

  Scenario: Routes carry the real 4-byte AS path on an AS4 session
    Given the test topology exists
    When I wait 20 seconds for BGP to operate
    Then show command "show bgp neighbor" in namespace "z1" should contain "4 Octet AS: advertised and received"
    And BGP route in "z2" has "10.0.0.1/32" with "as_path" value "1.4464"
    And BGP route in "z1" has "10.1.0.1/32" with "as_path" value "65002"

  Scenario: OLD speaker recovers the 4-byte AS path via AS4_PATH
    Given the test topology exists
    When I apply config "z2-2.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    # Hard reset (not the soft-out step): withholding the capability
    # only takes effect at the next OPEN exchange.
    And I run "clear bgp ipv4 neighbor 192.168.0.1" in namespace "z2"
    And I wait 30 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    # The session is genuinely OLD: z1 advertised the capability but z2
    # withheld it. Route-level assertions alone can't tell the two
    # apart — the AS4_PATH merge is designed to produce the same path.
    And show command "show bgp neighbor" in namespace "z1" should not contain "4 Octet AS: advertised and received"
    And show command "show bgp neighbor" in namespace "z1" should contain "4 Octet AS: advertised"
    And BGP route in "z2" has "10.0.0.1/32" with "as_path" value "1.4464"
    And BGP route in "z1" has "10.1.0.1/32" with "as_path" value "65002"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
