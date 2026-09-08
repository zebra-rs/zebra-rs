@serial
@bgp_rr_client_to_nonclient
Feature: A route reflector reflects a client's route to non-client iBGP peers (IPv4)
  As a network operator
  I want RFC 4456 §6 reflection in full: a route learned from a client
  goes to every other client AND to every non-client iBGP peer, while a
  route learned from a non-client goes to clients only
  So that the standard hierarchical design — reflectors that peer with
  each other as ordinary iBGP neighbors, each serving its own clients —
  actually carries every client's routes across the reflector tier.

  RFC 4456 §6, on receiving a route from an iBGP peer:
  - from a Non-Client: reflect to all the Clients;
  - from a Client: reflect to all the Non-Client peers and also to the
    Client peers other than the originator.
  Both reflected forms carry ORIGINATOR_ID (the originator's BGP
  Identifier) and CLUSTER_LIST (the reflector's cluster id prepended).

  zebra-rs kept no record of whether a path came from a client, and
  every egress builder gated iBGP-to-iBGP forwarding on the DESTINATION
  being a client alone — so the second bullet's "Non-Client peers" half
  never happened: a client's route reached the other clients and stopped
  at the reflector. Every reflector BDD until now made every iBGP
  neighbor a client, which is why it went unnoticed.

  Test Topology (one bridge, all AS 65001, z1 is the reflector):
  ```
  ┌───────────────────────────────────────────────────────────────────┐
  │                               br0                                 │
  └────┬──────────────┬──────────────┬──────────────┬──────────────┬──┘
   ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐      ┌───┴───┐
   │  z2   │      │  z3   │      │  z1   │      │  z4   │      │  z5   │
   │client │      │client │      │  RR   │      │non-cl.│      │non-cl.│
   │ id .2 │      │ id .3 │      │ id .1 │      │ id .4 │      │ id .5 │
   └───────┘      └───────┘      └───────┘      └───────┘      └───────┘
  ```
  Router-ids are 10.50.0.N; session addresses are 192.168.50.N.

  - z2 (client) originates 10.20.0.0/24; z3 is a client that only listens.
  - z4 (non-client) originates 10.40.0.0/24; z5 is a non-client that only listens.

  Config files:
  - z1.yaml: reflector — z2, z3 route-reflector clients; z4, z5 plain iBGP.
  - z2.yaml / z2-withdrawn.yaml: client, with and without its network.
  - z3.yaml, z5.yaml: listeners. z4.yaml: non-client originator.

  Scenario: Setup topology and establish all four sessions
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.50.1/24" on bridge "br0"
    And I create namespace "z2" with IP "192.168.50.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.50.3/24" on bridge "br0"
    And I create namespace "z4" with IP "192.168.50.4/24" on bridge "br0"
    And I create namespace "z5" with IP "192.168.50.5/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I start zebra-rs in namespace "z3"
    And I start zebra-rs in namespace "z4"
    And I start zebra-rs in namespace "z5"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I apply config "z3.yaml" to namespace "z3"
    And I apply config "z4.yaml" to namespace "z4"
    And I apply config "z5.yaml" to namespace "z5"
    Then BGP session in "z1" to "192.168.50.2" should eventually be "Established"
    And BGP session in "z1" to "192.168.50.3" should eventually be "Established"
    And BGP session in "z1" to "192.168.50.4" should eventually be "Established"
    And BGP session in "z1" to "192.168.50.5" should eventually be "Established"

  Scenario: Client to client — the other client receives the reflected route (control)
    Given the test topology exists
    Then show command "show bgp" in namespace "z3" should eventually contain "10.20.0.0/24"
    And show command "show bgp 10.20.0.0/24" in namespace "z3" should eventually contain "Originator: 10.50.0.2"
    And show command "show bgp 10.20.0.0/24" in namespace "z3" should contain "Cluster list:"

  Scenario: Non-client to client — the clients receive the reflected route (control)
    Given the test topology exists
    Then show command "show bgp" in namespace "z2" should eventually contain "10.40.0.0/24"
    And show command "show bgp" in namespace "z3" should eventually contain "10.40.0.0/24"
    And show command "show bgp 10.40.0.0/24" in namespace "z3" should eventually contain "Originator: 10.50.0.4"
    And show command "show bgp 10.40.0.0/24" in namespace "z3" should contain "Cluster list:"

  Scenario: Client to non-client — every non-client iBGP peer receives the client's route
    Given the test topology exists
    # RFC 4456 §6, second bullet: "reflect to all the Non-Client peers".
    # z4 and z5 are ordinary iBGP neighbors of the reflector.
    Then show command "show bgp" in namespace "z4" should eventually contain "10.20.0.0/24"
    And show command "show bgp" in namespace "z5" should eventually contain "10.20.0.0/24"
    And show command "show bgp 10.20.0.0/24" in namespace "z4" should eventually contain "Originator: 10.50.0.2"
    And show command "show bgp 10.20.0.0/24" in namespace "z4" should contain "Cluster list:"
    And show command "show bgp 10.20.0.0/24" in namespace "z5" should contain "Originator: 10.50.0.2"

  Scenario: Non-client to non-client — a non-client's route is NOT reflected to another non-client (control)
    Given the test topology exists
    # Wait until the non-client route has demonstrably been reflected (to
    # a client) before asserting its absence at the other non-client, so
    # "not contain" cannot pass merely because nothing happened yet.
    Then show command "show bgp" in namespace "z3" should eventually contain "10.40.0.0/24"
    And show command "show bgp" in namespace "z5" should not contain "10.40.0.0/24"

  Scenario: Withdrawing the client's route removes it from the non-clients too
    Given the test topology exists
    When I apply config "z2-withdrawn.yaml" to namespace "z2"
    Then show command "show bgp" in namespace "z4" should eventually not contain "10.20.0.0/24"
    And show command "show bgp" in namespace "z5" should eventually not contain "10.20.0.0/24"
    And show command "show bgp" in namespace "z3" should eventually not contain "10.20.0.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I stop zebra-rs in namespace "z3"
    And I stop zebra-rs in namespace "z4"
    And I stop zebra-rs in namespace "z5"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete namespace "z3"
    And I delete namespace "z4"
    And I delete namespace "z5"
    And I delete bridge "br0"
    Then the test environment should be clean
