@serial
@interface_bridge
Feature: Interface-to-bridge enslavement (`interface <if-name> bridge <bridge>`)
  As a network operator
  I want `interface <if-name> bridge <bridge>` to enslave a port to a bridge
  So that the binding is staged and applied once both the interface and the
  bridge exist — config order is free (equivalent to
  `ip link set <if-name> master <bridge>`).

  The binding is durable desired-state, mirroring `interface <if-name> vrf
  <vrf>`: it survives the bridge being created AFTER the interface config, an
  explicit unbind clears it, and the bridge being deleted then re-created
  re-applies it. We drive config with `apply command` (surgical set/delete)
  and assert the kernel state via `ip -o link show <if>` — `show interface`
  does not expose the master.

  Topology: one namespace `z1` with a single `dummy` port `dum0`. The bridge
  is created by the daemon from config (a namespace-internal kernel device),
  so no host-side bridge/veth scoping is needed.

  Scenario: Setup namespace with a dummy port
    Given a clean test environment
    When I create namespace "z1"
    And I execute "ip link add dum0 type dummy" in namespace "z1"
    And I execute "ip link set dum0 up" in namespace "z1"
    And I start zebra-rs in namespace "z1"

  # Scenario A: bind staged before the bridge exists, applied on bridge create.
  Scenario: A - binding set before the bridge exists is applied once it is created
    Given the test topology exists
    When I apply command "set interface dum0 bridge br0" in namespace "z1"
    And I wait 2 seconds
    # The bridge does not exist yet, so the bind stays pending: no master.
    Then command "ip -o link show dum0" in namespace "z1" should not contain "master"
    When I apply command "set bridge br0" in namespace "z1"
    # Bridge created -> the pending bind fires and enslaves dum0.
    Then command "ip -o link show dum0" in namespace "z1" should eventually contain "master br0"
    # reset
    When I apply command "delete interface dum0 bridge br0" in namespace "z1"
    And I apply command "delete bridge br0" in namespace "z1"
    Then command "ip -o link show dum0" in namespace "z1" should eventually not contain "master"

  # Scenario B: an unbind clears the pending intent so a later bridge does NOT enslave.
  Scenario: B - unbind clears the pending binding before the bridge appears
    Given the test topology exists
    When I apply command "set interface dum0 bridge br1" in namespace "z1"
    And I wait 2 seconds
    Then command "ip -o link show dum0" in namespace "z1" should not contain "master"
    When I apply command "delete interface dum0 bridge br1" in namespace "z1"
    And I apply command "set bridge br1" in namespace "z1"
    And I wait 3 seconds
    # Pending was cleared, so creating br1 must NOT enslave dum0.
    Then command "ip -o link show dum0" in namespace "z1" should not contain "master"
    # reset
    When I apply command "delete bridge br1" in namespace "z1"

  # Scenario C: the binding is durable across a bridge delete + re-create.
  Scenario: C - binding survives the bridge being deleted and re-binds on re-create
    Given the test topology exists
    When I apply command "set interface dum0 bridge br2" in namespace "z1"
    And I apply command "set bridge br2" in namespace "z1"
    Then command "ip -o link show dum0" in namespace "z1" should eventually contain "master br2"
    When I apply command "delete bridge br2" in namespace "z1"
    # Bridge gone -> kernel releases the port; the intent stays pending.
    Then command "ip -o link show dum0" in namespace "z1" should eventually not contain "master"
    When I apply command "set bridge br2" in namespace "z1"
    # Re-created -> the retained pending bind re-applies.
    Then command "ip -o link show dum0" in namespace "z1" should eventually contain "master br2"
    # reset
    When I apply command "delete interface dum0 bridge br2" in namespace "z1"
    And I apply command "delete bridge br2" in namespace "z1"
    Then command "ip -o link show dum0" in namespace "z1" should eventually not contain "master"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    Then the test environment should be clean
