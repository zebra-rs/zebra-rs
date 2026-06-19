@serial
@vxlan_bridge
Feature: VXLAN-to-bridge enslavement (`vxlan <name> bridge <bridge>`)
  As a network operator
  I want `vxlan <name> bridge <bridge>` to enslave a VXLAN device to a bridge
  So that an EVPN-style bridge port is set up in one step, with the VXLAN
  bridge-slave defaults applied automatically.

  This reuses the same staged bridge-bind as `interface <name> bridge
  <bridge>` (a VXLAN is an ordinary kernel link), so config order is free.
  In addition, binding a VXLAN to a bridge must yield the defaults from the
  iproute2 recipe:
    ip link set <vni> master <BR> addrgenmode none
    ip link set <vni> type bridge_slave neigh_suppress on learning off
  - `addrgenmode none` is the VXLAN creation default.
  - `neigh_suppress on` + `learning off` are applied by
    `vxlan_bridge_port_defaults` when the VXLAN gains a bridge master.

  We assert kernel state via `ip -d link show <vni>` (the `-d` detail view
  exposes addrgenmode and the bridge_slave port options).

  Scenario: Setup namespace with a VXLAN device
    Given a clean test environment
    When I create namespace "z1"
    And I execute "ip link add dum0 type dummy" in namespace "z1"
    And I execute "ip addr add 10.0.0.1/24 dev dum0" in namespace "z1"
    And I execute "ip link set dum0 up" in namespace "z1"
    And I start zebra-rs in namespace "z1"
    And I apply command "set vxlan vni550 vni 550" in namespace "z1"
    And I apply command "set vxlan vni550 local-address 10.0.0.1" in namespace "z1"
    And I wait 2 seconds
    # The VXLAN device exists with addrgenmode none even before any bridge.
    Then command "ip -d link show vni550" in namespace "z1" should eventually contain "addrgenmode none"

  # Scenario A: binding applies master + all bridge-slave defaults.
  Scenario: A - binding applies master and the VXLAN bridge-slave defaults
    Given the test topology exists
    When I apply command "set bridge br0" in namespace "z1"
    And I apply command "set vxlan vni550 bridge br0" in namespace "z1"
    Then command "ip -d link show vni550" in namespace "z1" should eventually contain "master br0"
    And command "ip -d link show vni550" in namespace "z1" should eventually contain "neigh_suppress on"
    And command "ip -d link show vni550" in namespace "z1" should eventually contain "learning off"
    And command "ip -d link show vni550" in namespace "z1" should eventually contain "addrgenmode none"
    # reset
    When I apply command "delete vxlan vni550 bridge br0" in namespace "z1"
    And I apply command "delete bridge br0" in namespace "z1"
    Then command "ip -d link show vni550" in namespace "z1" should eventually not contain "master"

  # Scenario B: binding set before the bridge exists is applied on create,
  # with the same defaults (config order is free).
  Scenario: B - deferred bind applies the defaults once the bridge is created
    Given the test topology exists
    When I apply command "set vxlan vni550 bridge br1" in namespace "z1"
    And I wait 2 seconds
    Then command "ip -d link show vni550" in namespace "z1" should not contain "master"
    When I apply command "set bridge br1" in namespace "z1"
    Then command "ip -d link show vni550" in namespace "z1" should eventually contain "master br1"
    And command "ip -d link show vni550" in namespace "z1" should eventually contain "neigh_suppress on"
    And command "ip -d link show vni550" in namespace "z1" should eventually contain "learning off"
    And command "ip -d link show vni550" in namespace "z1" should eventually contain "addrgenmode none"
    # reset
    When I apply command "delete vxlan vni550 bridge br1" in namespace "z1"
    And I apply command "delete bridge br1" in namespace "z1"
    Then command "ip -d link show vni550" in namespace "z1" should eventually not contain "master"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    Then the test environment should be clean
