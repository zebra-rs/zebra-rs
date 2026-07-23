@serial
@bgp_vrf_neighbor_next_hop
Feature: Per-VRF BGP neighbor per-AFI next-hop knobs (next-hop-self, next-hop-unchanged)
  As an operator of an L3VPN PE
  I want `router bgp vrf <name> neighbor <addr> afi-safi ipv4
  {next-hop-self | next-hop-unchanged}` to take effect on the plain
  IPv4-unicast advertise toward a CE
  So that the per-neighbor next-hop policy works on a PE-CE session — the
  knobs used to be honored only on the VPNv4 / labeled-unicast paths and
  were silently ignored for plain unicast.

  CE1 advertises 10.0.1.1/32 with its own address 10.1.0.2 as the next-hop.
  PE1 re-advertises it from the VRF Loc-RIB to the other CEs:
   * CE2 (eBGP, next-hop-unchanged) — keeps CE1's 10.1.0.2
   * CE3 (eBGP, default)            — rewrites to self, 10.3.0.1 (control)
   * CE4 (iBGP, next-hop-self)      — forces self, 10.4.0.1 (default iBGP
     would have preserved 10.1.0.2)

  Test Topology (5 namespaces, all CE links in vrf-cust):
  ```
   ce1(65001) ─┐
   ce2(65002) ─┼─ pe1 (65000, vrf-cust)
   ce3(65003) ─┤
   ce4(65000) ─┘   (ce4 is iBGP)
  ```

  Scenario: Build the next-hop VRF topology
    Given a clean test environment
    When I create namespace "ce1"
    And I create namespace "pe1"
    And I create namespace "ce2"
    And I create namespace "ce3"
    And I create namespace "ce4"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I connect namespace "pe1" interface "ce2" to namespace "ce2" interface "pe1"
    And I connect namespace "pe1" interface "ce3" to namespace "ce3" interface "pe1"
    And I connect namespace "pe1" interface "ce4" to namespace "ce4" interface "pe1"
    And I start zebra-rs in namespace "ce1"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "ce2"
    And I start zebra-rs in namespace "ce3"
    And I start zebra-rs in namespace "ce4"
    And I apply config "ce1.yaml" to namespace "ce1"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "ce2.yaml" to namespace "ce2"
    And I apply config "ce3.yaml" to namespace "ce3"
    And I apply config "ce4.yaml" to namespace "ce4"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "ce1" to "10.1.0.1" should eventually be "Established"
    And BGP session in "ce2" to "10.2.0.1" should eventually be "Established"
    And BGP session in "ce3" to "10.3.0.1" should eventually be "Established"
    And BGP session in "ce4" to "10.4.0.1" should eventually be "Established"

  Scenario: next-hop-unchanged preserves the received next-hop toward an eBGP CE
    Given the test topology exists
    Then show command "show bgp 10.0.1.1/32" in namespace "ce2" should eventually contain "10.1.0.2"

  Scenario: default eBGP advertisement rewrites the next-hop to self
    # Control for next-hop-unchanged: without the knob, CE3 sees PE1's own
    # address (10.3.0.1) as the next-hop, not CE1's 10.1.0.2.
    Given the test topology exists
    Then show command "show bgp 10.0.1.1/32" in namespace "ce3" should eventually contain "10.3.0.1"
    And show command "show bgp 10.0.1.1/32" in namespace "ce3" should not contain "10.1.0.2"

  Scenario: next-hop-self forces self toward an iBGP CE
    # CE4 is iBGP; the default would preserve CE1's 10.1.0.2, but
    # next-hop-self forces PE1's own address 10.4.0.1 (which CE4 can
    # actually resolve).
    Given the test topology exists
    Then show command "show bgp 10.0.1.1/32" in namespace "ce4" should eventually contain "10.4.0.1"
    And show command "show bgp 10.0.1.1/32" in namespace "ce4" should not contain "10.1.0.2"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "ce2"
    And I stop zebra-rs in namespace "ce3"
    And I stop zebra-rs in namespace "ce4"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    And I delete namespace "ce2"
    And I delete namespace "ce3"
    And I delete namespace "ce4"
    Then the test environment should be clean
