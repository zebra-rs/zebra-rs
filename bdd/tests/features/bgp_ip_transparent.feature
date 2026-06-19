@serial
@bgp_ip_transparent
Feature: BGP neighbor ip-transparent (peer as an address the host does not own)
  As a network operator
  I want a BGP session sourced from an address the host does not own
  (`update-source <foreign-addr>`) to stay down by default — the kernel
  refuses the non-local bind — and to establish once `ip-transparent`
  puts IP_TRANSPARENT on the session socket, confirming the knob
  end-to-end (FRR 10.4 `neighbor X ip-transparent`, mirroring its
  bgp_tcp_ip_transparent topotest).

  Test Topology:
  ```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────────────┐
           │   z1    │     │   z2            │
           │ AS65001 │     │ AS65002         │
           │ 10.0.0. │     │ 10.0.0.2/24     │
           │  1/24   │     │ peers AS        │
           │         │     │ 10.255.0.99     │
           │         │     │ (owned by NOBODY)│
           └─────────┘     └─────────────────┘
  ```

  z2 dials z1 sourcing the session from 10.255.0.99 — an address that is
  configured on no interface anywhere. z1 peers with 10.255.0.99 and has
  a static return route toward it via z2's real address. z2 carries the
  TPROXY-style return-path policy routing (inbound TCP fwmark → table
  100 `local default dev lo`, installed by a harness step) so packets to
  the phantom address reach its sockets; the ONLY remaining blocker is
  the kernel's non-local bind / source checks, which is precisely what
  `ip-transparent` lifts — making it the discriminating knob of the
  scenario pair. z1's own active side is held by the eBGP connected
  check (10.255.0.99 is not on a connected subnet), so z2 owns the
  connect direction.

  Config files:
  - z1.yaml: neighbor 10.255.0.99, static return route.
  - z2-base.yaml: update-source 10.255.0.99, no ip-transparent.
  - z2-transparent.yaml: same, plus `ip-transparent`.

  Scenario: A non-local update-source keeps the session down without ip-transparent
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "10.0.0.1/24" on bridge "br0"
    And I create namespace "z2" with IP "10.0.0.2/24" on bridge "br0"
    And I enable transparent return-path routing in namespace "z2"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2-base.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z2" to "10.0.0.1" should not be "Established"
    And BGP session in "z1" to "10.255.0.99" should not be "Established"
    And BGP route in "z2" does not have "10.1.1.1/32"

  Scenario: ip-transparent lets the session establish from the foreign address
    Given the test topology exists
    When I apply config "z2-transparent.yaml" to namespace "z2"
    And I wait 20 seconds for BGP to operate
    Then BGP session in "z2" to "10.0.0.1" should be "Established"
    And BGP session in "z1" to "10.255.0.99" should be "Established"
    And BGP route in "z1" has "10.2.2.2/32"
    And BGP route in "z2" has "10.1.1.1/32"
    And show command "show bgp neighbor" in namespace "z2" should contain "IP transparent enabled"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    And I delete bridge "br0"
    Then the test environment should be clean
