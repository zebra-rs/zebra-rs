@serial
@bgp_vpnv4_rr_transit_label
Feature: A VPNv4 route reflector programs no MPLS transit label
  A route reflector that only relays VPNv4 between iBGP clients passes
  every route through with the originating PE's next-hop and VPN label
  unchanged: it is never in the forwarding path, so it must not allocate
  a per-route local label nor install a swap ILM for it. Only a router
  that rewrites the next-hop to itself — an Inter-AS Option B transit
  ASBR, modelled here by turning `next-hop-self` on at the reflector —
  needs those, and it needs them for the routes it already holds the
  moment the knob is turned on, and must drop them again when it is
  turned off.

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
     │ no VRF) │     │10.1.0/24│     │10.2.0/24│
     │  .1     │     │  .2     │     │  .3     │
     └─────────┘     └─────────┘     └─────────┘
              192.168.0.0/24, VPNv4 iBGP pe→rr
  ```

  Scenario: Setup topology and establish the VPNv4 sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "rr" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "pe1" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "pe2" with IP "192.168.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "rr"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "pe2"
    And I apply config "rr.yaml" to namespace "rr"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "pe2.yaml" to namespace "pe2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "rr" to "192.168.0.2" should be "Established"
    And BGP session in "rr" to "192.168.0.3" should be "Established"

  Scenario: The reflector relays the VPN routes and programs no MPLS label
    Given the test topology exists
    Then show command "show bgp vpnv4" in namespace "rr" should eventually contain "10.1.0.0/24"
    And show command "show bgp vpnv4" in namespace "rr" should eventually contain "10.2.0.0/24"
    # Each PE imports the other's prefix via the reflector, with the
    # originating PE as next-hop — the reflector rewrote nothing.
    And show command "show ip route vrf vrf-cust" in namespace "pe2" should eventually contain "10.1.0.0/24"
    And show command "show ip route vrf vrf-cust" in namespace "pe2" should contain "192.168.0.2"
    And show command "show ip route vrf vrf-cust" in namespace "pe1" should eventually contain "10.2.0.0/24"
    And show command "show ip route vrf vrf-cust" in namespace "pe1" should contain "192.168.0.3"
    # The reflector holds every VPN route yet owns no label: nothing it
    # advertised carries a label of its own, so there is nothing to swap.
    And mpls ilm in namespace "rr" should be empty

  Scenario: next-hop-self turns the reflector into a transit and labels the routes it already holds
    Given the test topology exists
    When I apply command "set router bgp neighbor 192.168.0.3 afi-safi vpnv4 next-hop-self true" in namespace "rr"
    And I wait 5 seconds for BGP to operate
    # The rows learned before the knob was set are labelled and their
    # swap ILMs installed ...
    Then mpls ilm in namespace "rr" should not be empty
    # ... and pe2 is re-advertised pe1's prefix with the reflector as
    # next-hop, carrying the label that ILM swaps.
    And show command "show ip route vrf vrf-cust" in namespace "pe2" should eventually contain "192.168.0.1"

  Scenario: Removing next-hop-self releases the transit labels again
    Given the test topology exists
    When I apply command "delete router bgp neighbor 192.168.0.3 afi-safi vpnv4 next-hop-self" in namespace "rr"
    And I wait 5 seconds for BGP to operate
    Then mpls ilm in namespace "rr" should be empty
    And show command "show ip route vrf vrf-cust" in namespace "pe2" should eventually contain "192.168.0.2"

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
