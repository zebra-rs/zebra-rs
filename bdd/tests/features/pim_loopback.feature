@pim_loopback
Feature: PIM on a loopback forms no neighbors
  PIM runs on lo so that the router's own addresses, such as an RP
  address, sit on a PIM interface. A loopback has no segment to speak
  on: a Hello sent there comes straight back, from whatever source the
  kernel picked. 127.0.0.1 is host-scope, so with no address of its own
  on lo the kernel takes another interface's, and p1 listed itself as a
  neighbor on lo. A configured lo address raced the same way, until its
  AddrAdd reached PIM. A loopback is now passive, as in OSPF and IS-IS:
  it sends and accepts no Hellos.

  The kernel lists 127.0.0.1 and ::1 first on lo, so PIM showed lo by
  them and used them as its DR. A loopback address names the host, not a
  link: it now comes last, and lo is known by the address given to it.

  Test Topology:
  ```
    p1 (lo; eth1 10.1.12.1/24) --- veth --- p2 (eth2 10.1.12.2/24)
  ```

  Scenario: p1 runs PIM on lo and meets p2 on eth1
    Given a clean test environment
    When I create namespace "p1"
    And I create namespace "p2"
    And I connect namespace "p1" interface "eth1" to namespace "p2" interface "eth2"
    And I start zebra-rs in namespace "p1"
    And I start zebra-rs in namespace "p2"
    And I apply config "p1.yaml" to namespace "p1"
    And I apply config "p2.yaml" to namespace "p2"
    Then show command "show pim neighbor" in namespace "p1" should eventually contain "10.1.12.2"
    And show command "show pim interface" in namespace "p1" should contain "lo           Up"

  # p1 sent its first Hello on lo when the interface came up, before p2
  # was configured, so by now main had listed p1 on lo as 10.1.12.1, and
  # as 0.0.0.0 for a Hello sent before eth1 had its address.
  Scenario: p1 is not its own neighbor on lo
    Given the test topology exists
    Then show command "show pim neighbor" in namespace "p1" should not contain "10.1.12.1"

  Scenario: lo is known by the address given to it
    Given the test topology exists
    When I apply command "set interface lo ipv4 address 10.0.0.1/32" in namespace "p1"
    And I apply command "set interface lo ipv6 address 2001:db8::1/128" in namespace "p1"
    Then show command "show pim interface" in namespace "p1" should eventually contain "lo           Up      10.0.0.1         10.0.0.1"
    And show command "show pim ipv6 interface" in namespace "p1" should eventually contain "lo           Up      2001:db8::1      2001:db8::1"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "p1"
    And I stop zebra-rs in namespace "p2"
    And I delete namespace "p1"
    And I delete namespace "p2"
    Then the test environment should be clean
