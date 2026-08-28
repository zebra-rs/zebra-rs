@serial
@bgp_otc_local_role
Feature: BGP Roles and Only-to-Customer route-leak prevention (RFC 9234)
  As a network operator
  I want `neighbor X otc-local-role {customer|provider|peer|route-server-client} [strict]`
  So route leaks are prevented and detected from the BGP Role negotiated
  in the OPEN and the Only-to-Customer (OTC) attribute on the routes.

  Test Topology (a line, all eBGP, distinct ASes):
  ```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │ i2────────────i1 │   z3    │
   │ AS65001 │                  │ AS65002 │                  │ AS65003 │
   │ .0.1    │                  │.0.2 .1.2│                  │ .1.3    │
   └─────────┘                  └─────────┘                  └─────────┘
   originates 10.0.0.1/32
  ```

  z1 originates 10.0.0.1/32. The roles configured on each session decide
  what happens to that route (RFC 9234 §5):

    * ER1: z1 (provider) stamps OTC-AS 65001 toward its customer z2.
    * ER2: z2 (customer toward z3, i.e. z3 is a provider) must not
      advertise an OTC-marked route to z3.
    * IR3: with no role on z1, z2 (customer, loose mode) infers z1 as a
      provider and stamps OTC-AS 65001 on receipt itself.
    * IR1: z3 (provider, so z2 is its customer) rejects an OTC-marked
      route from z2 as a leak.
    * IR2: z3 (peer) rejects an OTC-marked route from z2 whose OTC-AS
      (65001) is not z2's AS (65002).
    * Role Mismatch: provider/provider is not a valid pair — the session
      is refused with a Role Mismatch NOTIFICATION; strict mode refuses a
      neighbor that sends no role at all.

  The IOS XR spellings are used throughout (`OTC Local Mode`, `OTC Remote
  Role: X (received|inferred)`, `OTC-AS`).

  Config files:
  - z1-base.yaml / z1-provider.yaml / z1-provider-strict.yaml
  - z2-customer-customer.yaml / z2-customer-norole.yaml / z2-provider.yaml / z2-norole.yaml
  - z3-base.yaml / z3-provider.yaml / z3-peer.yaml

  Scenario: Setup line topology, provider -> customer -> (customer toward) z3
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I create namespace "z3"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I connect namespace "z2" interface "i2" to namespace "z3" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1-provider.yaml" to namespace "z1"
    And I apply config "z2-customer-customer.yaml" to namespace "z2"
    And I apply config "z3-base.yaml" to namespace "z3"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z2" to "192.168.0.1" should be "Established"
    And BGP session in "z2" to "192.168.1.3" should be "Established"
    And BGP session in "z3" to "192.168.1.2" should be "Established"

  Scenario: Roles are exchanged in the OPEN and shown IOS XR style
    Given the test topology exists
    Then show command "show bgp neighbor" in namespace "z1" should contain "OTC Local Role : Provider"
    And show command "show bgp neighbor" in namespace "z1" should contain "OTC Remote Role: Customer (received)"
    And show command "show bgp neighbor" in namespace "z1" should contain "OTC Role: advertised (Provider) and received (Customer)"
    And show command "show bgp neighbor" in namespace "z2" should contain "OTC Remote Role: Provider (received)"

  Scenario: ER1 stamps OTC toward the customer and ER2 blocks it toward the next provider
    Given the test topology exists
    # z1 (provider) adds OTC-AS 65001 on egress toward its customer z2.
    Then BGP route in "z2" has "10.0.0.1/32" with "otc_as" value "65001"
    And show command "show bgp 10.0.0.1/32" in namespace "z2" should contain "OTC-AS: 65001"
    # z2 is a customer of z3, so z3 is a provider: an OTC-marked route
    # must not be advertised there (ER2).
    And BGP route in "z3" does not have "10.0.0.1/32"

  Scenario: IR3 stamps OTC on receipt from an inferred provider (loose mode)
    Given the test topology exists
    # Remove z1's role: it no longer sends a Role capability nor OTC. z2
    # (customer, loose) infers z1 as a provider and stamps OTC-AS 65001
    # itself on ingress.
    When I apply config "z1-base.yaml" to namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "192.168.0.1" should be "Established"
    And show command "show bgp neighbor" in namespace "z2" should contain "OTC Remote Role: Provider (inferred)"
    And BGP route in "z2" has "10.0.0.1/32" with "otc_as" value "65001"
    And BGP route in "z3" does not have "10.0.0.1/32"

  Scenario: IR1 rejects an OTC-marked route arriving from a customer
    Given the test topology exists
    # z2 drops its role toward z3, so it forwards the OTC-marked route
    # untouched; z3 becomes a provider (z2 is its customer) and must treat
    # the OTC-marked route as a leak (IR1).
    When I apply config "z2-customer-norole.yaml" to namespace "z2"
    And I apply config "z3-provider.yaml" to namespace "z3"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z3" to "192.168.1.2" should be "Established"
    And BGP route in "z3" does not have "10.0.0.1/32"
    And show command "show bgp neighbor" in namespace "z3" should not contain "By OTC ingress rule 1: 0,"

  Scenario: IR2 rejects an OTC-marked route from a peer whose OTC-AS is not the peer's AS
    Given the test topology exists
    # z3 as a peer of z2: the route still carries OTC-AS 65001 (z1), not
    # z2's 65002, so z3 rejects it (IR2).
    When I apply config "z3-peer.yaml" to namespace "z3"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z3" to "192.168.1.2" should be "Established"
    And BGP route in "z3" does not have "10.0.0.1/32"
    And show command "show bgp neighbor" in namespace "z3" should not contain "By OTC ingress rule 2: 0"

  Scenario: A route without OTC passes a peer and is stamped by ER1 toward it
    Given the test topology exists
    # No roles anywhere on z2: nothing is stamped on z2 and z2 forwards
    # whatever z1 sends. With z1 role-less the route reaches z3 unmarked,
    # and z3 (peer) stamps OTC-AS 65002 on ingress (IR3).
    When I apply config "z2-norole.yaml" to namespace "z2"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z3" to "192.168.1.2" should be "Established"
    And BGP route in "z2" has "10.0.0.1/32" without OTC
    And BGP route in "z3" has "10.0.0.1/32" with "otc_as" value "65002"

  Scenario: Provider/provider is a Role Mismatch and the session is refused
    Given the test topology exists
    When I apply config "z1-provider.yaml" to namespace "z1"
    And I apply config "z2-provider.yaml" to namespace "z2"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should not be "Established"
    And show command "show bgp neighbor" in namespace "z1" should contain "OTC Role Mismatch: received Provider, local Provider"

  Scenario: Strict mode refuses a neighbor that sends no role, loose accepts it
    Given the test topology exists
    When I apply config "z1-provider-strict.yaml" to namespace "z1"
    And I apply config "z2-norole.yaml" to namespace "z2"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should not be "Established"
    And show command "show bgp neighbor" in namespace "z1" should contain "OTC Local Mode: Strict"
    And show command "show bgp neighbor" in namespace "z1" should contain "no BGP Role capability received (strict mode)"
    # Back to loose: the same role-less neighbor is accepted, inferred.
    When I apply config "z1-provider.yaml" to namespace "z1"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And show command "show bgp neighbor" in namespace "z1" should contain "OTC Remote Role: Customer (inferred)"

  # Pure P2P links (no bridge): deleting each namespace destroys the veth
  # pair ends it holds, so only the daemons and namespaces need teardown.
  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    Then the test environment should be clean
