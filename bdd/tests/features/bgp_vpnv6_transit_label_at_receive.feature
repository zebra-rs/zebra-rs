@serial
@bgp_vpnv6_transit_label_at_receive
Feature: A VPNv6 transit configured before any route arrives labels the routes at receive
  The ordering twin of `bgp_vpnv6_rr_transit_label`, whose transit knob
  is turned on after the routes are in the table (so the reconcile labels
  them). Here the reflector is an Option B transit toward pe2 from its
  initial configuration: the shard's label pool is still empty when the
  first VPNv6 route arrives, so the receive path itself must draw a
  label from the central block and program the swap ILM. Review
  follow-up on finding #8: the live VPNv6 ingest handed the shard no
  central allocator, so nothing was minted, and the route went to pe2
  behind the reflector's next-hop with pe1's label — a label the
  reflector holds no ILM for.

  Test Topology: as `bgp_vpnv6_rr_transit_label` (rr / pe1 / pe2 on one
  bridge; VPNv6 sessions over IPv4, a global IPv6 per link as next-hop).

  Scenario: Setup topology with the reflector already a transit toward pe2
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "rr" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "pe1" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "pe2" with IP "192.168.0.3/24" on bridge "br0"
    And I execute "ip -6 addr add 2001:db8::1/64 dev vrrns" in namespace "rr"
    And I execute "ip -6 addr add 2001:db8::2/64 dev vpe1ns" in namespace "pe1"
    And I execute "ip -6 addr add 2001:db8::3/64 dev vpe2ns" in namespace "pe2"
    And I start zebra-rs in namespace "rr"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "pe2"
    And I apply config "rr.yaml" to namespace "rr"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "pe2.yaml" to namespace "pe2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "rr" to "192.168.0.2" should be "Established"
    And BGP session in "rr" to "192.168.0.3" should be "Established"

  Scenario: The route received under transit reaches pe2 behind the reflector with a swap ILM behind it
    Given the test topology exists
    Then show command "show bgp vpnv6" in namespace "rr" should eventually contain "2001:db8:1::/64"
    And show command "show bgp vpnv6" in namespace "pe2" should eventually contain "2001:db8:1::/64"
    And show command "show bgp vpnv6" in namespace "pe2" should contain "2001:db8::1"
    # The label pe2 was handed is one the reflector swaps: minted at
    # receive from the central block, with its ILM installed.
    And mpls ilm in namespace "rr" should not be empty

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "rr"
    And I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "pe2"
    And I delete namespace "rr"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete bridge "br0"
    Then the test environment should be clean
