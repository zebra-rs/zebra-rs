@isis_vrf_late_enslave
@isis
Feature: IS-IS per-VRF interface config that precedes the VRF enslavement
  As a network operator
  I want `router isis vrf <name> interface <if>` config to take effect even
  when the interface joins the VRF only after the per-VRF IS-IS instance has
  already started, so that config order (or the kernel's timing) never
  silently leaves a circuit unconfigured.

  Mechanism under test: a per-VRF IS-IS child subscribes to the RIB with a
  link dump limited to interfaces already enslaved to its VRF, then replays
  its config. Every `interface <name> …` callback resolves the link by
  name, so a line naming an interface the child has not seen yet used to
  be dropped on the floor — the circuit never came up, or (when the
  kernel's link update landed mid-replay) only the lines after it applied,
  leaving e.g. `circuit-type level-2-only` unapplied. A link appearing
  after `is-type` was set also kept the L1L2 link default, since only
  `is-type` and `circuit-type` changes recomputed a circuit's level. The same window opens
  inside a single commit: the RIB learns the enslavement from the netlink
  echo on one channel while the child's subscribe arrives on another, with
  no ordering between them. Deferred lines are now parked and replayed
  when the link appears.

  Test Topology:
  ```
     z1 [vrf-a: i1 10.0.12.1/30] ──── i1 10.0.12.2/30 [z2, lo 10.0.0.2/32]
  ```
  Commit 1 on z1 declares `vrf vrf-a` and the full `router isis vrf vrf-a`
  block for i1 while i1 is still in the default VRF. Commit 2 enslaves i1.

  Scenario: Setup z1 with IS-IS in a VRF whose interface is not yet enslaved
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then show command "show vrf" in namespace "z1" should eventually contain "vrf-a"
    And show command "show isis vrf vrf-a interface" in namespace "z1" should eventually not contain "i1"

  Scenario: Enslaving the interface afterwards brings the configured circuit up
    Given the test topology exists
    When I apply command "set interface i1 vrf vrf-a" in namespace "z1"
    Then show command "show isis vrf vrf-a interface" in namespace "z1" should eventually contain "i1"
    # The circuit runs at the instance's level-2-only, not the L1L2 link
    # default — is-type was configured before i1 existed in the VRF.
    And show command "show isis vrf vrf-a interface" in namespace "z1" should eventually not contain "L1L2"
    And show command "show isis vrf vrf-a neighbor" in namespace "z1" should eventually contain "Up"
    And show command "show ip route vrf vrf-a" in namespace "z1" should eventually contain "10.0.0.2/32"
    And daemon log in namespace "z1" should eventually contain "replaying 4 deferred config line(s)"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
