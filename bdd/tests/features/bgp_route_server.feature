@serial
@bgp_route_server
Feature: BGP route server (RFC 7947) — transparent re-advertisement to clients
  As an IXP operator
  I want `neighbor X route-server-client`
  So my route server re-advertises members' routes to each other with the
  originating member's AS_PATH and next-hop untouched.

  Test Topology (one exchange LAN, all eBGP):
  ```
  ┌────────────────────────────────────────────────────────────┐
  │                            br0                             │
  └──────────┬──────────────────┬──────────────────┬───────────┘
             │                  │                  │
        ┌────┴────┐        ┌────┴────┐        ┌────┴────┐
        │   z1    │        │   rs    │        │   z3    │
        │ AS65001 │        │ AS65000 │        │ AS65003 │
        │  .0.1   │        │  .0.2   │        │  .0.3   │
        └─────────┘        └─────────┘        └─────────┘
   originates 10.0.0.1/32                originates 10.0.0.3/32
  ```

  z1 and z3 peer only with the route server `rs`. As a plain eBGP
  speaker, rs prepends AS65000 and rewrites the next-hop to itself. With
  `route-server-client` on both sessions it becomes transparent: z3 sees
  10.0.0.1/32 with AS_PATH "65001" and next-hop 192.168.0.1 — z1 itself —
  and forwards to z1 directly across the LAN. Combined with RFC 9234, the
  server takes `otc-local-role route-server` and the members
  `route-server-client`, so the server marks routes with OTC-AS 65000.

  Config files:
  - z1.yaml / z3.yaml:        members originating one prefix each
  - z1-otc.yaml / z3-otc.yaml: same, with `otc-local-role route-server-client`
  - rs-base.yaml:              plain eBGP toward both members
  - rs-client.yaml:            `route-server-client` toward both
  - rs-client-otc.yaml:        plus `otc-local-role route-server`

  Scenario: Setup the exchange LAN with a plain eBGP "server"
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I create namespace "rs" with IP "192.168.0.2/24" on bridge "br0"
    And I create namespace "z3" with IP "192.168.0.3/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "rs"
    And I start zebra-rs in namespace "z3"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "rs-base.yaml" to namespace "rs"
    And I apply config "z3.yaml" to namespace "z3"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "rs" to "192.168.0.1" should be "Established"
    And BGP session in "rs" to "192.168.0.3" should be "Established"
    And BGP session in "z1" to "192.168.0.2" should be "Established"
    And BGP session in "z3" to "192.168.0.2" should be "Established"

  Scenario: A plain eBGP speaker prepends its AS and rewrites the next-hop
    Given the test topology exists
    Then BGP route in "z3" has "10.0.0.1/32" with "as_path" value "65000 65001"
    And BGP route in "z3" has "10.0.0.1/32" with "next_hop" value "192.168.0.2"
    And BGP route in "z1" has "10.0.0.3/32" with "as_path" value "65000 65003"

  Scenario: route-server-client makes the server transparent both ways
    Given the test topology exists
    When I apply config "rs-client.yaml" to namespace "rs"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "rs" to "192.168.0.1" should be "Established"
    And BGP session in "rs" to "192.168.0.3" should be "Established"
    And show command "show bgp neighbor" in namespace "rs" should contain "Route-server client: enabled"
    # RFC 7947 §2.2.2 / §2.2.1: the originating member's AS_PATH and
    # next-hop reach the other member untouched.
    And BGP route in "z3" has "10.0.0.1/32" with "as_path" value "65001"
    And BGP route in "z3" has "10.0.0.1/32" with "next_hop" value "192.168.0.1"
    And BGP route in "z1" has "10.0.0.3/32" with "as_path" value "65003"
    And BGP route in "z1" has "10.0.0.3/32" with "next_hop" value "192.168.0.3"

  Scenario: RFC 9234 route-server / route-server-client roles on top
    Given the test topology exists
    When I apply config "rs-client-otc.yaml" to namespace "rs"
    And I apply config "z1-otc.yaml" to namespace "z1"
    And I apply config "z3-otc.yaml" to namespace "z3"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "rs" to "192.168.0.1" should be "Established"
    And BGP session in "rs" to "192.168.0.3" should be "Established"
    And show command "show bgp neighbor" in namespace "rs" should contain "OTC Remote Role: Route Server Client (received)"
    And show command "show bgp neighbor" in namespace "z3" should contain "OTC Remote Role: Route Server (received)"
    # ER1 on the server (RS toward RS-client): OTC = the server's AS.
    And BGP route in "z3" has "10.0.0.1/32" with "otc_as" value "65000"
    And BGP route in "z3" has "10.0.0.1/32" with "as_path" value "65001"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "rs"
    And I stop zebra-rs in namespace "z3"
    And I delete namespace "z1"
    And I delete namespace "rs"
    And I delete namespace "z3"
    And I delete bridge "br0"
    Then the test environment should be clean
