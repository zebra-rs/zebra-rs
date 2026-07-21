@serial
@bgp_dynamic_nbr_policy
Feature: A dynamic (listen-range) peer inherits its neighbor-group's route policy
  As a network operator
  I want the `policy` bound on a listen-range's neighbor-group
  So every peer materialized from that range is filtered like a static member.

  Test Topology:
  ```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐
   │   z2    │ i1────────────i1 │   z1    │
   │ AS65002 │                  │ AS65001 │
   │ .0.2    │                  │ .0.1    │
   └─────────┘                  └─────────┘
  ```

  z1 (the DUT) has no static neighbors; z2 arrives via the listen-range
  and inherits SENDERS. With SENDERS carrying `policy in DENY-ALL` the
  session must still establish, z1's own route must still flow out —
  but z2's route must be denied on ingress. Rebinding the group without
  the policy and re-materializing the peer readmits the route, proving
  the policy is resolved from the group at accept time, not baked in.

  Config files:
  - z1-deny.yaml: DUT — SENDERS has `policy in DENY-ALL`, originates 10.0.1.1/32
  - z1-open.yaml: identical but the group carries no policy binding
  - z2.yaml:      client, static neighbor to .0.1, originates 10.0.2.2/32

  Scenario: Establish with an inbound deny-all policy inherited from the group
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z2" interface "i1" to namespace "z1" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1-deny.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z1" to "192.168.0.2" should be "Established"
    # Policy filters routes, not the session: outbound is untouched...
    And BGP route in "z2" has "10.0.1.1/32"
    # ...while the inherited inbound DENY-ALL drops the client's route.
    And BGP route in "z1" does not have "10.0.2.2/32"

  Scenario: Unbinding the group policy readmits the route on re-materialization
    Given the test topology exists
    When I apply config "z1-open.yaml" to namespace "z1"
    And I wait 10 seconds
    # Hard-reset from the client: z1's dynamic peer is torn down and the
    # reconnect materializes a fresh peer that resolves the group's
    # CURRENT (policy-less) state through the same accept-time ritual.
    And I run "clear bgp ipv4 neighbor 192.168.0.1" in namespace "z2"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP route in "z1" has "10.0.2.2/32"
    And BGP route in "z2" has "10.0.1.1/32"

  # Pure P2P topology (no bridge): deleting each namespace destroys the
  # veth pair ends it holds, so only daemons and namespaces need teardown.
  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
