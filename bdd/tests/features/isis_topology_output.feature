@serial
@isis_topology_output
Feature: show isis topology renders the FRR SPF-tree layout

  `show isis topology` lists the SPF tree as FRR does: every router,
  pseudonode, and prefix is a vertex, ordered by SPF metric. Three L2
  routers (a1, a2, a3) share one LAN (br0); a3 (LAN priority 100) is the
  DIS. The layout must show:

    - the DIS's pseudonode as a distinct "pseudo_TE-IS" vertex (not a
      duplicate "TE-IS" of the DIS's own router vertex),
    - the local router's own prefixes as "IP internal" at metric 0 — these
      come from the self LSP because the reach-map skips self, so a missing
      self-prefix path drops them entirely,
    - remote prefixes as "IP TE".

  Scenario: the SPF tree lists self-prefixes, the pseudonode, and remote prefixes
    Given a clean test environment
    When I create bridge "br0"
    And I create namespace "a1" with IP "192.168.100.1/24" on bridge "br0"
    And I create namespace "a2" with IP "192.168.100.2/24" on bridge "br0"
    And I create namespace "a3" with IP "192.168.100.3/24" on bridge "br0"
    And I start zebra-rs in namespace "a1"
    And I start zebra-rs in namespace "a2"
    And I start zebra-rs in namespace "a3"
    And I apply config "a1.yaml" to namespace "a1"
    And I apply config "a2.yaml" to namespace "a2"
    And I apply config "a3.yaml" to namespace "a3"
    And I wait 20 seconds
    # a3 (priority 100) is DIS, so its pseudonode is a distinct vertex.
    Then show command "show isis topology" in namespace "a1" should eventually contain "pseudo_TE-IS"
    # a1's own loopback appears as an "IP internal" self-prefix (read from
    # the self LSP; the reach-map skips self, so the bug dropped this row).
    And show command "show isis topology" in namespace "a1" should eventually contain "10.0.0.1/32"
    And show command "show isis topology" in namespace "a1" should eventually contain "IP internal"
    # Remote prefixes are "IP TE".
    And show command "show isis topology" in namespace "a1" should eventually contain "IP TE"
    # The DIS's own view also lists its pseudonode.
    And show command "show isis topology" in namespace "a3" should eventually contain "pseudo_TE-IS"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "a1"
    And I stop zebra-rs in namespace "a2"
    And I stop zebra-rs in namespace "a3"
    And I delete namespace "a1"
    And I delete namespace "a2"
    And I delete namespace "a3"
    And I delete bridge "br0"
    Then the test environment should be clean
