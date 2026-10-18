@rib_link_route_interface
Feature: A route with no gateway names its interface in every RIB view
  A connected route, and a kernel route out of an interface with no
  gateway, carry their interface in the RIB entry; the nexthop holds no
  interface of its own. The one-line views read the entry, but the JSON
  and the detail view read the nexthop and named the interface
  "unknown". An IPv4 route added out of an interface (scope link) is
  filed as connected; an IPv6 one is a kernel route.

  Test Topology:
  ```
   host ── z1 (vc1: 172.16.10.1/24, 2001:db8:10::1/64)
           ip route add 10.9.9.0/24 / 2001:db8:9::/64 dev vc1
  ```

  Config files:
  - z1.yaml: vc1's addresses only; no routing protocol runs.

  Scenario: Build the router
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "host"
    And I connect namespace "z1" interface "vc1" to namespace "host" interface "eth0"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"
    Then show command "show ip route" in namespace "z1" should eventually contain "172.16.10.0/24 is directly connected, vc1"

  Scenario: A connected route's JSON nexthop names its interface
    Given the test topology exists
    Then show command "show ip route 172.16.10.0/24" as JSON in namespace "z1" should eventually contain '"interface": "vc1"'
    And show command "show ipv6 route 2001:db8:10::/64" as JSON in namespace "z1" should eventually contain '"interface": "vc1"'

  Scenario: An IPv4 route added out of an interface is connected and names it
    Given the test topology exists
    When I execute "ip route add 10.9.9.0/24 dev vc1" in namespace "z1"
    Then show command "show ip route" in namespace "z1" should eventually contain "10.9.9.0/24 is directly connected, vc1"
    And show command "show ip route 10.9.9.0/24" as JSON in namespace "z1" should eventually contain '"interface": "vc1"'

  Scenario: An IPv6 kernel route out of an interface names it in detail and JSON
    Given the test topology exists
    When I execute "ip -6 route add 2001:db8:9::/64 dev vc1" in namespace "z1"
    Then show command "show ipv6 route" in namespace "z1" should eventually contain "2001:db8:9::/64 [0/1024] via vc1"
    And show command "show ipv6 route detail" in namespace "z1" should eventually contain "directly attached via vc1"
    And show command "show ipv6 route 2001:db8:9::/64" as JSON in namespace "z1" should eventually contain '"interface": "vc1"'

  Scenario: Teardown
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete namespace "host"
    Then the test environment should be clean
