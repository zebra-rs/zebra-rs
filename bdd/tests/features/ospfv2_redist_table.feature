@serial
@ospfv2_redist_table
Feature: OSPFv2 redistributes routes from a kernel routing table
  As a network operator
  I want `redistribute table <id>` (FRR parity) to import routes the
  kernel holds in a non-main routing table — installed externally
  via `ip route ... table N` — as Type-5 AS-External LSAs, tracking
  the table live: routes added later originate, deleted ones flush.

  Test Topology:
  ```
    r1 -- 10.0.12.0/30 -- r2 (redistribute table 100, metric 30)
    table 100 on r2 (unicast dev-lo routes): 10.55.1.0/24
    (pre-start, covers the netlink dump path) and 10.55.2.0/24
    (added live, covers the monitor delta path).
  ```

  Scenario: Kernel-table routes originate as externals and track live changes
    Given a clean test environment
    When I create namespace "r1"
    And I create namespace "r2"
    And I connect namespace "r1" interface "ethb" to namespace "r2" interface "etha"
    # Installed BEFORE the daemon starts: exercised via the startup
    # netlink route dump. (Unicast device routes — the RIB's netlink
    # parse accepts only unicast kinds.)
    And I execute "ip link set lo up" in namespace "r2"
    And I execute "ip route add 10.55.1.0/24 dev lo table 100" in namespace "r2"
    And I start zebra-rs in namespace "r1"
    And I start zebra-rs in namespace "r2"
    And I apply config "r1.yaml" to namespace "r1"
    And I apply config "r2.yaml" to namespace "r2"
    And I wait 25 seconds

    Then show command "show ospf neighbor" in namespace "r1" should contain "Full"
    # The pre-start table route arrives on r1 as an external at the
    # configured metric.
    And show command "show ospf route" in namespace "r1" should eventually contain "10.55.1.0/24"
    And show command "show ospf route" in namespace "r1" should contain "[30]"

    # A route added to the table while everything runs must
    # originate live (netlink monitor -> RIB table store -> OSPF).
    When I execute "ip route add 10.55.2.0/24 dev lo table 100" in namespace "r2"
    Then show command "show ospf route" in namespace "r1" should eventually contain "10.55.2.0/24"

    # And a deleted one must flush its Type-5 live.
    When I execute "ip route del 10.55.1.0/24 dev lo table 100" in namespace "r2"
    Then show command "show ospf route" in namespace "r1" should eventually not contain "10.55.1.0/24"
    And show command "show ospf route" in namespace "r1" should contain "10.55.2.0/24"

  Scenario: Teardown topology
    # Separate scenario so cleanup still runs when a step above fails
    # (a failed step skips the rest of its own scenario only).
    When I stop zebra-rs in namespace "r1"
    And I stop zebra-rs in namespace "r2"
    And I delete namespace "r1"
    And I delete namespace "r2"
    Then the test environment should be clean
