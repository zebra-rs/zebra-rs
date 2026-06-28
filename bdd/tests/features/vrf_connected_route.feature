@vrf_connected_route
Feature: A VRF interface's connected route lands in the VRF table
  When an interface is enslaved to a VRF and carries an IPv4 address,
  the connected route derived from that address must be installed into
  the VRF's routing table — not the default table. The interface is
  enslaved asynchronously (the kernel acknowledges `master` via a later
  RTM_NEWLINK), so the connected route is often first filed in the
  default table and must be re-homed onto the VRF table once the enslave
  is observed. Regression test for: connected route shown in
  `show ip route` but missing from `show ip route vrf <name>`.

  ```
   host(172.16.10.2) ── z1[vrf N3] (172.16.10.1, static 172.16.20.0/24)
  ```

  Scenario: Connected route of a VRF interface is in the VRF table only
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "host"
    And I connect namespace "z1" interface "vc1" to namespace "host" interface "eth0"
    And I add address "172.16.10.2/24" to interface "eth0" in namespace "host"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"
    And I wait 5 seconds
    # The fix: the connected prefix is present in the VRF table…
    Then show command "show ip route vrf N3" in namespace "z1" should contain "172.16.10.0/24"
    # …and the on-link VRF static route resolves against it.
    And show command "show ip route vrf N3" in namespace "z1" should contain "172.16.20.0/24"
    # The default table must NOT carry the VRF interface's connected route.
    And show command "show ip route" in namespace "z1" should not contain "172.16.10.0/24"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete namespace "host"
    Then the test environment should be clean
