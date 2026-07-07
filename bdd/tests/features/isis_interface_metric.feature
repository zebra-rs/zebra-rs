@isis_interface_metric
@isis
Feature: IS-IS connected-prefix reachability reflects the interface metric
  As a network operator
  I want the IS-IS interface `metric` to apply not only to the IS
  reachability (adjacency cost) but also to the IPv4 (TLV 135) and
  IPv6 (TLV 236) reachability advertised for that interface's connected
  prefixes, so a non-default interface metric raises the advertised cost
  of the attached subnets the same way FRR / IOS-XR do — rather than a
  fixed metric 10 regardless of configuration.

  Test Topology (dual-stack, single-topology L2 over a shared bridge):
  ```
  ┌────────────────────────────────────────┐
  │                  br0                   │
  └────────────┬───────────────┬───────────┘
               │               │
        10.0.1.1/24        10.0.1.2/24
     2001:db8:1::1/64   2001:db8:1::2/64
            (vz1ns)             (vz2ns)
          ┌────┴────┐     ┌────┴────┐
          │   z1    │     │   z2    │
          └─────────┘     └─────────┘
   lo: 10.0.0.1/32          lo: 10.0.0.2/32
   2001:db8:0:ffff::1/128   2001:db8:0:ffff::2/128
  ```

  Both configs set `metric 55` on the vzXns interface (a non-default
  value; the default is 10). The connected prefixes 10.0.1.0/24 and
  2001:db8:1::/64 must therefore appear in the LSPs with Metric 55.
  The loopbacks leave `metric` unset, so they stay at the default 10 —
  a built-in contrast that proves the metric is applied per interface.

  Scenario: Setup dual-stack IS-IS L2 with a non-default interface metric
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with loopback and veth interface on the bridge "br0"
    And I create namespace "z2" with loopback and veth interface on the bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-1.yaml" to namespace "z1"
    And I apply config "z2-1.yaml" to namespace "z2"
    And I wait 20 seconds
    Then ping from "z1" to "10.0.0.2" should succeed
    And ping from "z2" to "2001:db8:0:ffff::1" should succeed

  Scenario: IPv4 connected prefix (TLV 135) carries the interface metric
    Given the test topology exists
    Then show command "show isis database detail" in namespace "z1" should contain "Extended IP Reachability: 10.0.1.0/24 (Metric: 55)"
    And show command "show isis database detail" in namespace "z2" should contain "Extended IP Reachability: 10.0.1.0/24 (Metric: 55)"

  Scenario: IPv6 connected prefix (TLV 236) carries the interface metric
    Given the test topology exists
    Then show command "show isis database detail" in namespace "z1" should contain "IPv6 Reachability: 2001:db8:1::/64 (Metric: 55)"
    And show command "show isis database detail" in namespace "z2" should contain "IPv6 Reachability: 2001:db8:1::/64 (Metric: 55)"

  Scenario: The loopback prefixes keep the default metric 10
    Given the test topology exists
    Then show command "show isis database detail" in namespace "z1" should contain "Extended IP Reachability: 10.0.0.1/32 (Metric: 10)"
    And show command "show isis database detail" in namespace "z1" should contain "IPv6 Reachability: 2001:db8:0:ffff::1/128 (Metric: 10)"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
