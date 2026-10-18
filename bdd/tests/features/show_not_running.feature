@show_not_running
Feature: A show command for a subsystem that is not running names it
  A show command goes to the task that serves it. When that task is not
  running, the daemon answers "<name> is not configured or running".
  The names sat in a list of their own, apart from the routing, which
  missed two subsystems: `show ebpf` without the eBPF data plane, and
  `show pim`, `show igmp` or `show mroute` without PIM, all read
  "Unknown protocol is not configured or running". The names now come
  from the routing table itself.

  Test Topology:
  ```
   z1   (nothing configured: no protocol and no eBPF data plane runs)
  ```

  Scenario: Start the daemon with nothing configured
    Given a clean test environment
    When I create namespace "z1"
    And I start zebra-rs in namespace "z1"
    Then show command "show bgp summary" in namespace "z1" should eventually contain "BGP is not configured or running"

  Scenario: show ebpf without the eBPF data plane names it
    Given the test topology exists
    Then show command "show ebpf" in namespace "z1" should eventually contain "eBPF data plane is not configured or running"
    And show command "show ebpf stats" in namespace "z1" should eventually contain "eBPF data plane is not configured or running"

  Scenario: show pim, igmp and mroute without PIM name it
    Given the test topology exists
    Then show command "show pim" in namespace "z1" should eventually contain "PIM is not configured or running"
    And show command "show igmp groups" in namespace "z1" should eventually contain "PIM is not configured or running"
    And show command "show mroute" in namespace "z1" should eventually contain "PIM is not configured or running"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    Then the test environment should be clean
