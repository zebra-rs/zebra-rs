@serial
@dhcp_client_vrf
Feature: DHCPv4 client on an interface in a VRF

  A DHCP interface in a VRF leases through that VRF: the client's sockets
  are bound to the interface, and the lease's routes go to the VRF's
  table. Nothing of it reaches the default table.

  Topology:

      s1 (dnsmasq) srv0 192.0.2.1/24 ──── wan0 (vrf red, address dhcp) r1

  Config files:
  - r1.yaml: VRF red, wan0 in it, `address dhcp` on wan0.

  Scenario: Setup the server and a router whose DHCP uplink is in VRF red
    Given a clean test environment
    When I create namespace "s1"
    And I create namespace "r1"
    And I connect namespace "s1" interface "srv0" to namespace "r1" interface "wan0"
    And I execute "tests/scripts/dhcp_server.sh dhcp_client_vrf start srv0 192.0.2.1/24 192.0.2.100 192.0.2.150 120" in namespace "s1"
    And I start zebra-rs in namespace "r1"
    And I apply config "r1.yaml" to namespace "r1"
    Then show command "show dhcp client leases" in namespace "r1" should eventually contain "State:        bound"

  Scenario: The lease and its route are in the VRF only
    Given the test topology exists
    Then show command "show dhcp client leases" in namespace "r1" should contain "VRF:          red"
    And show command "show ip route vrf red" in namespace "r1" should eventually contain "0.0.0.0/0 [210/0] via 192.0.2.1, wan0"
    And show command "show ip route vrf red" in namespace "r1" should contain "192.0.2.0/24 is directly connected, wan0"
    And show command "show ip route" in namespace "r1" should not contain "0.0.0.0/0"
    And show command "show ip route" in namespace "r1" should not contain "192.0.2.0/24"

  Scenario: Release and renew stay in the VRF
    Given the test topology exists
    Then show command "release dhcp interface wan0" in namespace "r1" should contain "Released the DHCP lease on wan0"
    And show command "show ip route vrf red" in namespace "r1" should eventually not contain "0.0.0.0/0"
    And show command "renew dhcp interface wan0" in namespace "r1" should contain "Renewing"
    And show command "show ip route vrf red" in namespace "r1" should eventually contain "0.0.0.0/0 [210/0] via 192.0.2.1, wan0"
    And show command "show ip route" in namespace "r1" should not contain "0.0.0.0/0"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "r1"
    And I execute "tests/scripts/dhcp_server.sh dhcp_client_vrf stop" in namespace "s1"
    And I delete namespace "r1"
    And I delete namespace "s1"
    Then the test environment should be clean
