@serial
@isis_multi_topology
@isis
Feature: IS-IS multi-topology (RFC 5120)
  As a network operator
  I want two zebra-rs instances to participate in IS-IS multi-topology
  routing for IPv6 unicast (MT 2), exchanging TLV 229 / 222 / 237 in
  their LSPs and installing IPv6 reachability through the per-MT SPF
  result, so dual-stack networks can run independent IPv4 and IPv6
  topologies.

  Test Topology (same shape as isis_ipv6 but both sides emit MT TLVs):
  ```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
       2001:db8:1::1/64   2001:db8:1::2/64
            (vz1ns)             (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          │ +MT 2   │     │ +MT 2   │
          └─────────┘     └─────────┘
   lo: 2001:db8:0:ffff::1   lo: 2001:db8:0:ffff::2
              /128                  /128
  ```

  Both configs add `multi-topology ipv6-unicast;` under `router/isis/`
  so the LSPs carry TLV 229 (capability), TLV 222 (MT IS Reach), and
  TLV 237 (MT IPv6 Reach).

  Scenario: Setup IS-IS L2 with MT 2 over a shared bridge and confirm the link is up
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with loopback and veth interface on the bridge "br0"
    And I create namespace "z2" with loopback and veth interface on the bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 20 seconds
    Then ping from "z1" to "2001:db8:1::2" should succeed
    And ping from "z2" to "2001:db8:1::1" should succeed

  Scenario: MT 2 SPF installs reciprocal IPv6 routes to peer loopbacks
    Given the test topology exists
    Then ping from "z1" to "2001:db8:0:ffff::2" should succeed
    And ping from "z2" to "2001:db8:0:ffff::1" should succeed

  Scenario: LSPs carry the multi-topology TLVs
    Given the test topology exists
    Then show command "show isis database detail" in namespace "z1" should contain "Multi-Topology"
    And show command "show isis database detail" in namespace "z1" should contain "MT IPv6 Reachability (MT-ID 2)"
    And show command "show isis database detail" in namespace "z2" should contain "Multi-Topology"
    And show command "show isis database detail" in namespace "z2" should contain "MT IPv6 Reachability (MT-ID 2)"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
