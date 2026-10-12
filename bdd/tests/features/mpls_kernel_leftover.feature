@mpls_kernel_leftover
Feature: MPLS labels an earlier run left in the kernel
  zebra-rs reads the kernel's MPLS table at startup
  (docs/design/mpls-label-allocation.md §4, phase 7b). An ILM an earlier
  run left there, under one of zebra-rs's protocol numbers, after a crash
  say, is replaced by the ILM installed at its label now: the install
  used to fail with EEXIST, and the leftover went on forwarding. A label
  nobody replaces is handed out to nobody until it is swept, from the
  kernel and the label space.

  Test Topology: z1 alone on br0 (192.168.0.1/24); the gateways named
  are on its subnet.

  Scenario: A static binding replaces the ILM a crashed run left at its label
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "z1" with IP "192.168.0.1/24" on bridge "br0"
    And I start zebra-rs in namespace "z1"
    And I apply command "set router static mpls label 100 nexthop 192.168.0.2" in namespace "z1"
    Then command "ip -f mpls route show 100" in namespace "z1" should eventually contain "192.168.0.2"
    # A crash: the daemon goes, its ILM stays in the kernel.
    When I stop zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z1"
    And I apply command "set router static mpls label 100 nexthop 192.168.0.3" in namespace "z1"
    Then command "ip -f mpls route show 100" in namespace "z1" should eventually contain "192.168.0.3"
    And command "ip -f mpls route show 100" in namespace "z1" should not contain "192.168.0.2"
    And show command "show mpls ilm" in namespace "z1" should not contain "Earlier run"

  Scenario: A leftover's label is handed out to nobody until it is swept
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    # Another leftover: a BGP label at 24000, where BGP's first chunk
    # would start.
    And I execute "ip -f mpls route add 24000 via inet 192.168.0.9 proto bgp" in namespace "z1"
    And I start zebra-rs in namespace "z1" sweeping leftovers after 15 seconds
    And I apply config "z1.yaml" to namespace "z1"
    Then show command "show mpls label table" in namespace "z1" should eventually contain "24001-24128    bgp     block           held"
    And show command "show mpls label table" in namespace "z1" should contain "24000          bgp     leftover        stale"
    And show command "show mpls ilm" in namespace "z1" should contain "Earlier run"
    # Nothing replaces them, so they are swept: 24000, and the static
    # binding at 100 the last run installed, which this configuration
    # does not have.
    And show command "show mpls label table" in namespace "z1" should eventually not contain "leftover"
    And command "ip -f mpls route show" in namespace "z1" should not contain "192.168.0.9"
    And command "ip -f mpls route show" in namespace "z1" should not contain "192.168.0.3"
    And show command "show mpls ilm" in namespace "z1" should not contain "Earlier run"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I delete namespace "z1"
    And I delete bridge "br0"
    Then the test environment should be clean
