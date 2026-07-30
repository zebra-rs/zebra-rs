@serial
@vlan_interface
Feature: Config-created 802.1Q VLAN sub-interfaces
  As a network operator
  I want `set vlan <name> interface <parent>` + `vlan-id <1-4094>`
  So zebra-rs creates and owns the kernel VLAN device, deferring
  creation until the parent exists and re-creating it when a deleted
  parent returns.

  Topology: a single namespace with dummy parent interfaces.
  ```
   ┌──────────────────────────────┐
   │  z1                          │
   │  dum0 ── dum0.100 (vid 100)  │
   │  dum1 ── cust-a   (vid 200)  │   dum1 created AFTER the config
   └──────────────────────────────┘
  ```

  Config files:
  - z1.yaml: both VLAN entries; dum0 exists at apply time, dum1 does not

  Scenario: Setup namespace and create a VLAN on an existing parent
    Given a clean test environment
    When I create namespace "z1"
    And I execute "ip link add dum0 type dummy" in namespace "z1"
    And I execute "ip link set dum0 up" in namespace "z1"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"
    # Poll listings (`ip … show` with no device argument): naming a not-
    # yet-created device makes `ip` exit nonzero, which the command step
    # treats as a hard failure instead of a retry.
    Then command "ip link show" in namespace "z1" should eventually contain "dum0.100@dum0"
    And command "ip -d link show" in namespace "z1" should eventually contain "vlan protocol 802.1Q id 100"
    And show command "show interface dum0.100" in namespace "z1" should eventually contain "VLAN id 100 parent dum0"
    And command "ip link show" in namespace "z1" should not contain "cust-a"

  Scenario: Creation defers until the parent appears
    Given the test topology exists
    When I execute "ip link add dum1 type dummy" in namespace "z1"
    And I execute "ip link set dum1 up" in namespace "z1"
    Then command "ip link show" in namespace "z1" should eventually contain "cust-a@dum1"
    And command "ip -d link show" in namespace "z1" should eventually contain "vlan protocol 802.1Q id 200"
    And show command "show interface cust-a" in namespace "z1" should eventually contain "VLAN id 200 parent dum1"

  Scenario: The sub-interface takes addresses like any other interface
    Given the test topology exists
    # A follow-up commit, not the creating one: addresses on a device
    # created in the same commit are dropped (pre-existing limitation
    # shared with bridge/vxlan; the address exec is immediate while
    # device creation lands at CommitEnd + a netlink echo later).
    When I apply command "set interface dum0.100 ipv4 address 10.100.0.1/24" in namespace "z1"
    Then command "ip addr show dum0.100" in namespace "z1" should eventually contain "10.100.0.1/24"

  Scenario: A deleted parent takes the VLAN with it and its return re-creates the VLAN
    Given the test topology exists
    When I execute "ip link del dum0" in namespace "z1"
    Then command "ip link show" in namespace "z1" should eventually not contain "dum0.100"
    When I execute "ip link add dum0 type dummy" in namespace "z1"
    And I execute "ip link set dum0 up" in namespace "z1"
    Then command "ip link show" in namespace "z1" should eventually contain "dum0.100@dum0"
    And command "ip -d link show" in namespace "z1" should eventually contain "vlan protocol 802.1Q id 100"

  Scenario: Changing the VLAN id re-creates the kernel device
    Given the test topology exists
    # The device is deleted and re-made, so there is a window where it
    # does not exist — poll the listing, not the device.
    When I apply command "set vlan dum0.100 vlan-id 150" in namespace "z1"
    Then command "ip -d link show" in namespace "z1" should eventually contain "vlan protocol 802.1Q id 150"

  Scenario: Deleting the config entry deletes the kernel device
    Given the test topology exists
    When I apply command "delete vlan cust-a" in namespace "z1"
    Then command "ip link show" in namespace "z1" should eventually not contain "cust-a"

  # Single namespace, dummy parents only: deleting the namespace destroys
  # every device it holds, so only the daemon and namespace need teardown.
  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    Then the test environment should be clean
