@serial
@interface_vrf_binding
Feature: Interface-to-VRF enslavement (`interface <name> vrf <vrf>`)
  As a network operator
  I want to enslave individual interfaces to a VRF master device
  So that traffic on those interfaces is routed in the VRF's table instead
  of the default routing instance.

  The binding is operator intent, not an immediate netlink call: either
  half can be missing when the config is committed. `link_vrf_bind` records
  the intent in `pending_vrf_bind` and replays it when the missing piece
  arrives — a kernel `NewLink` for the interface, or `VrfAdd` for the
  master — so config order is free. That deferral is what scenarios D and
  E pin; the rest pin the steady state and the show surfaces.

  Kernel state is asserted with `ip -d link show <if>` (`master <vrf>`)
  rather than through zebra-rs, so a show-layer bug cannot make a missing
  enslavement look present.

  Test Topology:
  ```
              ┌─────────────────────────────┐
              │              z1             │
              │   ┌─────────────────────┐   │
              │   │      vrf vrf1       │   │  table-id allocated
              │   └──────────┬──────────┘   │
              │              │ master       │
              │   ┌──────────┴──────────┐   │
              │   │         vi1         │   │  192.168.10.1/24
              │   └─────────────────────┘   │
              │                             │
              │             vi2             │  10.0.0.1/24, default VRF
              └─────────────────────────────┘
  ```

  vi1 and vi2 are dummy interfaces created before the daemon starts; vi3 is
  created mid-run by scenario D to prove a binding survives the netdev not
  existing yet. vi2 never joins a VRF and is the control for the `default`
  rendering in `show interface brief`.

  Config files (in configs/interface_vrf_binding/):
  - z1.yaml: vrf1, vi1 enslaved to it with 192.168.10.1/24, unbound vi2.

  Scenario: Setup — a VRF master with one member, bound in a single commit
    Given a clean test environment
    When I create namespace "z1"
    And I execute "ip link add vi1 type dummy" in namespace "z1"
    And I execute "ip link set vi1 up" in namespace "z1"
    And I execute "ip link add vi2 type dummy" in namespace "z1"
    And I execute "ip link set vi2 up" in namespace "z1"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"
    # The VRF master device is created with a table id of its own.
    Then command "ip -d link show vrf1" in namespace "z1" should eventually contain "vrf table"
    # …and vi1 is enslaved to it.
    And command "ip -d link show vi1" in namespace "z1" should eventually contain "master vrf1"

  # The address and the binding arrived in one commit, so whichever the RIB
  # processes first, the connected prefix must end up in the VRF's table —
  # never left behind in the default one.
  Scenario: A - an address committed with the binding lands in the VRF table
    Given the test topology exists
    Then command "ip route show vrf vrf1" in namespace "z1" should eventually contain "192.168.10.0/24"
    And show command "show ip route vrf vrf1" in namespace "z1" should eventually contain "192.168.10.0/24"
    And show command "show ip route" in namespace "z1" should not contain "192.168.10.0/24"

  Scenario: B - show vrf lists the member and show interface brief names the VRF
    Given the test topology exists
    Then show command "show vrf" in namespace "z1" should eventually contain "vrf1"
    And show command "show vrf" in namespace "z1" should eventually contain "vi1"
    And show command "show interface brief" in namespace "z1" should eventually contain "vrf1"
    # vi2 was never bound, so it renders as the default routing instance.
    And show command "show interface brief" in namespace "z1" should eventually contain "default"

  # `delete` carries the leaf's value, like every other leaf in the grammar;
  # the bare `delete interface vi1 vrf` is rejected with an error reply.
  Scenario: C - unbinding returns the interface to the default VRF
    Given the test topology exists
    When I apply command "delete interface vi1 vrf vrf1" in namespace "z1"
    Then command "ip -d link show vi1" in namespace "z1" should eventually not contain "master vrf1"
    # The member column empties out with it.
    And show command "show vrf" in namespace "z1" should eventually not contain "vi1"
    # reset for the scenarios below
    When I apply command "set interface vi1 vrf vrf1" in namespace "z1"
    Then command "ip -d link show vi1" in namespace "z1" should eventually contain "master vrf1"

  # pending_vrf_bind replayed on NewLink: the binding is committed while the
  # netdev does not exist, and fires by itself the moment it is created.
  Scenario: D - a binding set before the netdev exists fires on create
    Given the test topology exists
    When I apply command "set interface vi3 vrf vrf1" in namespace "z1"
    And I wait 2 seconds
    # Nothing to enslave yet — the intent is parked, not lost.
    Then command "ip link show" in namespace "z1" should not contain "vi3"
    When I execute "ip link add vi3 type dummy" in namespace "z1"
    And I execute "ip link set vi3 up" in namespace "z1"
    Then command "ip -d link show vi3" in namespace "z1" should eventually contain "master vrf1"
    And show command "show vrf" in namespace "z1" should eventually contain "vi3"

  Scenario: E - re-binding moves the interface to a second VRF
    Given the test topology exists
    When I apply command "set vrf vrf2" in namespace "z1"
    And I apply command "set interface vi1 vrf vrf2" in namespace "z1"
    Then command "ip -d link show vi1" in namespace "z1" should eventually contain "master vrf2"
    And command "ip -d link show vi1" in namespace "z1" should eventually not contain "master vrf1"

  # Deleting the master is allowed with members still bound: the kernel
  # detaches them when the device goes. The operator never withdrew the
  # binding, though, so the intent outlives the VRF and re-creating it
  # re-enslaves vi3 with no second `set interface` — the VrfAdd half of
  # the deferred bind, the mirror of scenario D's NewLink half.
  Scenario: F - deleting the VRF detaches its members, re-creating re-enslaves
    Given the test topology exists
    When I apply command "delete vrf vrf1" in namespace "z1"
    Then command "ip -d link show vi3" in namespace "z1" should eventually not contain "master vrf1"
    And show command "show vrf" in namespace "z1" should eventually not contain "vrf1"
    # The binding was never withdrawn, so the master coming back is enough.
    When I apply command "set vrf vrf1" in namespace "z1"
    Then command "ip -d link show vi3" in namespace "z1" should eventually contain "master vrf1"
    And show command "show vrf" in namespace "z1" should eventually contain "vi3"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    Then the test environment should be clean
