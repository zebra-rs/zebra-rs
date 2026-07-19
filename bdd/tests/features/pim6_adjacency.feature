@serial
@pim6_adjacency
Feature: PIMv6 two-router neighborship forms over link-local transport
  As a network operator
  I want two zebra-rs routers to run PIMv6 on an IPv6 link and discover
  each other through link-local-sourced Hellos, so the PIMv6 transport
  (raw protocol 103 over IPv6, ff02::d joins, in6_pktinfo source
  pinning and the pseudo-header checksum) and the address-family split
  (`router pim ipv6` spawning a default-table Pim<Ipv6>) are exercised
  router-to-router.

  PIMv6 Hellos are sourced from the interface link-local (fe80::/10,
  RFC 7761 §4.3.1), so each router learns the peer as a link-local
  neighbor.

  Test Topology:
  ```
    p1 (2001:db8:12::1/64, fe80 auto) --- veth --- p2 (2001:db8:12::2/64, fe80 auto)
       eth1                                           eth2
  ```

  Scenario: Two PIMv6 routers discover each other over link-local
    Given a clean test environment
    When I create namespace "p1"
    And I create namespace "p2"
    And I connect namespace "p1" interface "eth1" to namespace "p2" interface "eth2"
    And I start zebra-rs in namespace "p1"
    And I start zebra-rs in namespace "p2"
    And I apply config "p1.yaml" to namespace "p1"
    And I apply config "p2.yaml" to namespace "p2"

    # Both interfaces run PIMv6 (the default-table Pim<Ipv6> child spawned
    # via the `router pim ipv6` address-family split).
    Then show command "show pim ipv6 interface" in namespace "p1" should eventually contain "Up"
    And show command "show pim ipv6 interface" in namespace "p2" should eventually contain "Up"

    # Each router learns the peer as a link-local neighbor — proving
    # Hellos were sourced from and matched against fe80:: addresses.
    And show command "show pim ipv6 neighbor" in namespace "p1" should eventually contain "fe80"
    And show command "show pim ipv6 neighbor" in namespace "p2" should eventually contain "fe80"

  Scenario: Teardown topology
    When I stop zebra-rs in namespace "p1"
    And I stop zebra-rs in namespace "p2"
    And I delete namespace "p1"
    And I delete namespace "p2"
    Then the test environment should be clean
