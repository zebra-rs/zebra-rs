@serial
@bgp_vpnv6_rr_transit_label
Feature: A VPNv6 next-hop-self transit advertises its own label and programs a swap ILM
  The VPNv6 twin of `bgp_vpnv4_rr_transit_label`. A route reflector that
  only relays VPNv6 between iBGP clients passes every route through with
  the originating PE's next-hop and VPN label unchanged and programs no
  MPLS ILM. A router that rewrites the next-hop to itself — an Inter-AS
  Option B transit ASBR, modelled here by turning `afi-safi vpnv6
  next-hop-self` on at the reflector — must advertise a label of ITS OWN
  and hold a swap ILM behind it, for the routes it already holds the
  moment the knob is turned on, and must drop both again when it is
  turned off. Review finding #8: VPNv6 had none of this — the received
  label went on the wire behind the transit's own next-hop, so the peer
  pushed a label the transit held no ILM for.

  Test Topology:
  ```
  ┌───────────────────────────────────────────────┐
  │                      br0                      │
  └───────┬───────────────┬───────────────┬───────┘
          │               │               │
     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
     │   rr    │     │   pe1   │     │   pe2   │
     │ AS64512 │     │ AS64512 │     │ AS64512 │
     │ (RR,    │     │vrf-cust │     │vrf-cust │
     │ no VRF) │     │db8:1::/64│    │db8:2::/64│
     │ .1 / ::1│     │ .2 / ::2│     │ .3 / ::3│
     └─────────┘     └─────────┘     └─────────┘
       192.168.0.0/24 (sessions) + 2001:db8::/64 (VPNv6 next-hops)
  ```

  Scenario: Setup topology and establish the VPNv6 sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "rr" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "pe1" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "pe2" with IP "192.168.0.3/24" on bridge "br0"
    # A global IPv6 address on each bridge link: the VPNv6 next-hop a PE
    # originates with, and the self address a next-hop-self rewrites to.
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

  Scenario: The reflector relays the VPNv6 routes and programs no MPLS label
    Given the test topology exists
    Then show command "show bgp vpnv6" in namespace "rr" should eventually contain "2001:db8:1::/64"
    And show command "show bgp vpnv6" in namespace "rr" should eventually contain "2001:db8:2::/64"
    # pe2 holds pe1's prefix with pe1 as next-hop — the reflector rewrote nothing.
    And show command "show bgp vpnv6" in namespace "pe2" should eventually contain "2001:db8:1::/64"
    And show command "show bgp vpnv6" in namespace "pe2" should contain "2001:db8::2"
    # The reflector holds every VPN route yet owns no label: nothing it
    # advertised carries a label of its own, so there is nothing to swap.
    And mpls ilm in namespace "rr" should be empty

  Scenario: next-hop-self turns the reflector into a VPNv6 transit and labels the routes it already holds
    Given the test topology exists
    When I apply command "set router bgp neighbor 192.168.0.3 afi-safi vpnv6 next-hop-self true" in namespace "rr"
    And I wait 5 seconds for BGP to operate
    # pe2 is re-advertised pe1's prefix with the reflector as next-hop ...
    Then show command "show bgp vpnv6" in namespace "pe2" should eventually contain "2001:db8::1"
    # ... carrying a label the reflector swaps: the rows learned before
    # the knob was set are labelled and their swap ILMs installed.
    And mpls ilm in namespace "rr" should not be empty

  Scenario: Removing next-hop-self releases the transit labels again
    Given the test topology exists
    When I apply command "delete router bgp neighbor 192.168.0.3 afi-safi vpnv6 next-hop-self" in namespace "rr"
    And I wait 5 seconds for BGP to operate
    Then mpls ilm in namespace "rr" should be empty
    And show command "show bgp vpnv6" in namespace "pe2" should eventually contain "2001:db8::2"

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
