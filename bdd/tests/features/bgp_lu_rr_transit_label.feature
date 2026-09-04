@serial
@bgp_lu_rr_transit_label
Feature: A labeled-unicast route reflector programs no MPLS transit label
  The Labeled-Unicast twin of bgp_vpnv4_rr_transit_label. A reflector
  that only relays BGP-LU between iBGP clients passes every route through
  with the originating client's next-hop and label unchanged: it is never
  in the forwarding path, so it must not allocate a per-prefix local label
  nor install a swap ILM for it. Only a router that rewrites the next-hop
  to itself — the Inter-AS Option C ASBR → PE leg, modelled here by
  turning `next-hop-self` on at the reflector — needs those, and it needs
  them for the routes it already holds the moment the knob is turned on,
  and must drop them again when it is turned off.

  Test Topology:
  ```
  ┌───────────────────────────────────────────────┐
  │                      br0                      │
  └───────┬───────────────┬───────────────┬───────┘
          │               │               │
     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
     │   rr    │     │   c1    │     │   c2    │
     │ AS64512 │     │ AS64512 │     │ AS64512 │
     │  (RR)   │     │lo1 10.1 │     │lo1 10.2 │
     │  .1     │     │ .0.1/32 │     │ .0.1/32 │
     └─────────┘     └─────────┘     └─────────┘
            192.168.0.0/24, label-v4 iBGP c→rr
  ```

  Scenario: Setup topology and establish the labeled-unicast sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "rr" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "c1" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "c2" with IP "192.168.0.3/24" on bridge "br0"
    And I create dummy interface "lo1" with address "10.1.0.1/32" in namespace "c1"
    And I create dummy interface "lo1" with address "10.2.0.1/32" in namespace "c2"
    And I start zebra-rs in namespace "rr"
    And I start zebra-rs in namespace "c1"
    And I start zebra-rs in namespace "c2"
    And I apply config "rr.yaml" to namespace "rr"
    And I apply config "c1.yaml" to namespace "c1"
    And I apply config "c2.yaml" to namespace "c2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "rr" to "192.168.0.2" should be "Established"
    And BGP session in "rr" to "192.168.0.3" should be "Established"

  Scenario: The reflector relays the labeled routes and programs no MPLS label
    Given the test topology exists
    Then show command "show bgp labeled-unicast" in namespace "rr" should eventually contain "10.1.0.1/32"
    And show command "show bgp labeled-unicast" in namespace "rr" should eventually contain "10.2.0.1/32"
    # Each client learns the other's loopback via the reflector and
    # installs it toward the originating client — the reflector rewrote
    # nothing.
    And show command "show ip route" in namespace "c2" should eventually contain "10.1.0.1/32"
    And show command "show ip route" in namespace "c2" should contain "192.168.0.2"
    And show command "show ip route" in namespace "c1" should eventually contain "10.2.0.1/32"
    And show command "show ip route" in namespace "c1" should contain "192.168.0.3"
    # The reflector holds every labeled route yet owns no label: nothing
    # it advertised carries a label of its own, so there is nothing to swap.
    And mpls ilm in namespace "rr" should be empty

  Scenario: next-hop-self turns the reflector into a transit and labels the routes it already holds
    Given the test topology exists
    When I apply command "set router bgp neighbor 192.168.0.3 afi-safi label-v4 next-hop-self true" in namespace "rr"
    And I wait 5 seconds for BGP to operate
    # The rows learned before the knob was set are labelled and their
    # swap ILMs installed ...
    Then mpls ilm in namespace "rr" should not be empty
    # ... and c2 is re-advertised c1's loopback with the reflector as
    # next-hop, carrying the label that ILM swaps.
    And show command "show ip route" in namespace "c2" should eventually contain "192.168.0.1"

  Scenario: Removing next-hop-self releases the transit labels again
    Given the test topology exists
    When I apply command "delete router bgp neighbor 192.168.0.3 afi-safi label-v4 next-hop-self" in namespace "rr"
    And I wait 5 seconds for BGP to operate
    Then mpls ilm in namespace "rr" should be empty
    And show command "show ip route" in namespace "c2" should eventually contain "192.168.0.2"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "rr"
    And I stop zebra-rs in namespace "c1"
    And I stop zebra-rs in namespace "c2"
    And I delete namespace "rr"
    And I delete namespace "c1"
    And I delete namespace "c2"
    And I delete bridge "br0"
    Then the test environment should be clean
