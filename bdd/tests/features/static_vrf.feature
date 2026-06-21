@static_vrf
Feature: Static routes inside a VRF (router static vrf NAME)
  A static route configured under `router static vrf <name>` installs
  into that VRF's kernel routing table and forwards traffic. Two hosts
  hang off one router's VRF, each reached by a per-VRF static route to
  its loopback; a ping between the host loopbacks proves the VRF static
  routes are installed and resolving on-link (the gateway sits on a VRF
  interface, whose connected route the kernel flushes on enslave — so
  this exercises the on-link `ifindex_origin` resolution path).

  ```
   hostA ── z1[vrf cust] ── hostB
   aa::1     (static vrf)    bb::1
  ```

  Scenario: Build topology and confirm the VRF static routes install
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "hostA"
    And I create namespace "hostB"
    And I connect namespace "z1" interface "ce1" to namespace "hostA" interface "eth0"
    And I connect namespace "z1" interface "ce2" to namespace "hostB" interface "eth0"
    And I make namespace "hostA" interface "lo" up
    And I make namespace "hostB" interface "lo" up
    And I add address "2001:db8:a::2/64" to interface "eth0" in namespace "hostA"
    And I add address "2001:db8:aa::1/128" to interface "lo" in namespace "hostA"
    And I add address "2001:db8:b::2/64" to interface "eth0" in namespace "hostB"
    And I add address "2001:db8:bb::1/128" to interface "lo" in namespace "hostB"
    And I add route "2001:db8:bb::1/128" via "2001:db8:a::1" in namespace "hostA"
    And I add route "2001:db8:b::/64" via "2001:db8:a::1" in namespace "hostA"
    And I add route "2001:db8:aa::1/128" via "2001:db8:b::1" in namespace "hostB"
    And I add route "2001:db8:a::/64" via "2001:db8:b::1" in namespace "hostB"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"
    And I wait 5 seconds
    Then show command "show ipv6 route vrf cust" in namespace "z1" should contain "2001:db8:aa::1/128"
    And show command "show ipv6 route vrf cust" in namespace "z1" should contain "2001:db8:bb::1/128"

  Scenario: Traffic forwards between the hosts via the VRF static routes
    Given the test topology exists
    Then ping from "hostA" to "2001:db8:bb::1" should eventually succeed
    And ping from "hostB" to "2001:db8:aa::1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete namespace "hostA"
    And I delete namespace "hostB"
    Then the test environment should be clean
