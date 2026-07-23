@serial
@bgp_vrf_neighbor_add_path
Feature: Per-VRF BGP neighbor AddPath send (RFC 7911)
  As an operator of an L3VPN PE with redundant CE uplinks
  I want `router bgp vrf <name> neighbor <addr> afi-safi ipv4 add-path
  send-receive` to advertise every VRF path for a prefix
  So that a CE that negotiated AddPath receives BOTH paths for a
  multi-homed prefix, not just the single best one — the per-VRF exercise
  of AddPath send / path-id stamping.

  CE1 (65001) and CE2 (65002) both advertise 10.10.10.0/24 into vrf-cust,
  so PE1's VRF Loc-RIB holds two candidate paths. With AddPath negotiated
  toward CE3, PE1 advertises both, so CE3 sees two paths — one via AS 65001
  and one via AS 65002. Without AddPath send CE3 would hold only the single
  best path (one AS_PATH).

  Test Topology (4 namespaces, CE links in vrf-cust):
  ```
   ce1(65001) ─┐
   ce2(65002) ─┼─ pe1 (65000, vrf-cust) ── ce3(65003, AddPath rx)
  ```

  Scenario: Build the AddPath VRF topology
    Given a clean test environment
    When I create namespace "ce1"
    And I create namespace "pe1"
    And I create namespace "ce2"
    And I create namespace "ce3"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I connect namespace "pe1" interface "ce2" to namespace "ce2" interface "pe1"
    And I connect namespace "pe1" interface "ce3" to namespace "ce3" interface "pe1"
    And I start zebra-rs in namespace "ce1"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "ce2"
    And I start zebra-rs in namespace "ce3"
    And I apply config "ce1.yaml" to namespace "ce1"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "ce2.yaml" to namespace "ce2"
    And I apply config "ce3.yaml" to namespace "ce3"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "ce1" to "10.1.0.1" should eventually be "Established"
    And BGP session in "ce2" to "10.2.0.1" should eventually be "Established"
    And BGP session in "ce3" to "10.3.0.1" should eventually be "Established"

  Scenario: PE1's VRF Loc-RIB holds both candidate paths
    Given the test topology exists
    Then show command "show bgp vrf vrf-cust 10.10.10.0/24" in namespace "pe1" should eventually contain "65001"
    And show command "show bgp vrf vrf-cust 10.10.10.0/24" in namespace "pe1" should eventually contain "65002"

  Scenario: The AddPath receiver sees both paths for the prefix
    # CE3 negotiated AddPath, so PE1 advertises both VRF paths — CE3 sees a
    # path via 65001 and a path via 65002 (each "65000 <ce-as>"). Both
    # checks poll: PE1 advertises the two AddPaths asynchronously.
    Given the test topology exists
    Then show command "show bgp 10.10.10.0/24" in namespace "ce3" should eventually contain "65000 65001"
    And show command "show bgp 10.10.10.0/24" in namespace "ce3" should eventually contain "65000 65002"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "ce2"
    And I stop zebra-rs in namespace "ce3"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    And I delete namespace "ce2"
    And I delete namespace "ce3"
    Then the test environment should be clean
