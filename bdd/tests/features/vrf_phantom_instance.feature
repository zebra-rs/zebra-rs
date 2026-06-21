@vrf_phantom_instance
Feature: A top-level VRF must not spawn a phantom per-protocol instance
  Configuring a top-level `vrf <name>` creates the kernel VRF master, but
  it is NOT a protocol per-VRF block — IS-IS and OSPF only own
  `/router/<proto>/vrf/<name>/…`. Because the config manager broadcasts
  every committed line to every protocol task, a too-greedy `vrf <name>`
  match used to make IS-IS/OSPF spawn a phantom per-VRF instance for a VRF
  that has no `router <proto> vrf` configuration. With the proto-anchored
  `vrf_config_split` they must not.

  This router has a top-level `vrf cust` plus IS-IS and OSPFv2 in the
  default VRF only. `show task` lists each running protocol and its VRF;
  it must show `isis` / `ospf` under `default` and never a `cust` row.

  ```
   z1: vrf cust (kernel master, no per-proto block)
       router isis  (default)
       router ospf  (default)
  ```

  Scenario: A bare top-level VRF spawns no per-VRF IS-IS / OSPF instance
    Given a clean test environment
    When I create namespace "z1"
    And I start zebra-rs in namespace "z1"
    And I apply config "z1.yaml" to namespace "z1"
    And I wait 5 seconds
    # Non-vacuous guard: the default instances are up, so the negative
    # assertion below is meaningful (the command really produced output).
    Then show command "show task" in namespace "z1" should contain "isis"
    And show command "show task" in namespace "z1" should contain "ospf"
    # The fix: no phantom per-VRF child registered for `cust` — the only
    # place a `cust` row could appear in `show task` is a per-VRF instance.
    And show command "show task" in namespace "z1" should not contain "cust"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    Then the test environment should be clean
