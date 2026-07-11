@cradle_spawn
Feature: system ebpf spawns and supervises the cradle eBPF engine
  `system ebpf enabled true` makes zebra-rs run the cradle data-plane
  daemon as a managed child: spawn it, attach `interface <name> ebpf
  enabled` ports, respawn it with backoff when it dies (re-attaching the
  ports and replaying the mirrored FIB tee), and stop it when disabled.

  Prerequisite: /usr/bin/cradle (the cradle-rs engine binary). Install it
  from a cradle-rs checkout: `cargo build --release` then
  `install -m755 target/release/cradle /usr/bin/cradle`.

  Topology:
  ```
   crs1 [ zebra-rs + managed cradle, eth0 ebpf port ] ─ eth0 ── eth0 ─ crs2
  ```

  Scenario: Managed engine spawns with a data-plane port
    Given a clean test environment
    When I create namespace "crs1"
    And I create namespace "crs2"
    And I connect namespace "crs1" interface "eth0" to namespace "crs2" interface "eth0"
    And I add address "10.210.1.1/24" to interface "eth0" in namespace "crs1"
    And I add address "10.210.1.2/24" to interface "eth0" in namespace "crs2"
    And I start zebra-rs in namespace "crs1"
    And I apply config "z1.yaml" to namespace "crs1"
    Then show command "show ebpf" in namespace "crs1" should eventually contain "managed"
    And show command "show ebpf" in namespace "crs1" should eventually contain "attached"
    And daemon log in namespace "crs1" should eventually contain "cradle: engine ready"

  Scenario: The engine's tables and counters render through show ebpf
    Given the test topology exists
    Then show command "show ebpf ipv4" in namespace "crs1" should eventually contain "10.210.99.0/24"
    And show command "show ebpf nexthop" in namespace "crs1" should eventually contain "10.210.1.2"
    And show command "show ebpf stats" in namespace "crs1" should eventually contain "l3v4_forward"
    And show command "show ebpf mpls" in namespace "crs1" should eventually contain "(empty)"

  Scenario: A crashed engine respawns, re-attaches the port, and replays the FIB
    Given the test topology exists
    When I execute "pkill -9 -x cradle" in namespace "crs1"
    Then daemon log in namespace "crs1" should eventually contain "cradle: engine exited"
    And daemon log in namespace "crs1" should eventually contain "fib: cradle replay:"
    And show command "show ebpf" in namespace "crs1" should eventually contain "Engine restarts: 1"
    And show command "show ebpf" in namespace "crs1" should eventually contain "attached"

  Scenario: A VRF-enslaved port binds to the VRF's kernel table
    Given the test topology exists
    When I apply command "set vrf red" in namespace "crs1"
    And I apply command "set interface eth0 vrf red" in namespace "crs1"
    Then show command "show ebpf" in namespace "crs1" should eventually contain "vrf 1"
    And show command "show ebpf" in namespace "crs1" should eventually contain "attached"
    When I apply command "delete interface eth0 vrf red" in namespace "crs1"
    Then show command "show ebpf" in namespace "crs1" should eventually not contain "vrf 1"
    And show command "show ebpf" in namespace "crs1" should eventually contain "attached"

  Scenario: Disabling system ebpf stops the engine
    Given the test topology exists
    When I apply command "delete system ebpf enabled true" in namespace "crs1"
    Then show command "show ebpf" in namespace "crs1" should eventually contain "off (system ebpf disabled)"
    And daemon log in namespace "crs1" should eventually contain "engine stopped (system ebpf disabled)"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "crs1"
    And I delete namespace "crs1"
    And I delete namespace "crs2"
    Then the test environment should be clean
