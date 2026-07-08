@serial
@isis_lan_dis_reelection
Feature: IS-IS LAN DIS re-election converges when priority changes

  Regression for a DIS-election convergence bug on a broadcast LAN.

  Three L2 routers (a1, a2, a3) share one LAN (br0), loopbacks
  10.0.0.{1,2,3}/32. a3 starts as DIS (LAN priority 100; a1/a2 at the
  default 64). Raising a1's LAN priority to 200 must move the DIS to a1 on
  *every* speaker while full loopback reachability is preserved.

  The bug: a non-DIS bystander (a2) that switched its elected DIS from a3
  to a1 while staying a non-DIS member (DisStatus Other -> Other) never
  re-registered its pseudonode adjacency — the adjacency update was gated
  on a DIS *status* change, and Other -> Other is not one. a2 kept
  pointing at a3's old pseudonode LSP, which the resigning DIS a3 had
  purged, so a2's SPF routed through a pseudonode that no longer existed
  and it lost the route to a1's loopback. The decisive assertions are
  that after the DIS moves, a2's interface adjacency points at a1's
  pseudonode (0000.0000.0001.*) and a2 still reaches 10.0.0.1/32.

  Scenario: raising a non-DIS router's priority moves the DIS and the LAN stays reachable
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
    # Baseline: a3 (priority 100) is DIS, so the bystander a2 points its
    # pseudonode adjacency at a3, and every loopback is reachable.
    Then show command "show isis interface" in namespace "a2" should eventually contain "0000.0000.0003."
    And show command "show isis route" in namespace "a1" should eventually contain "10.0.0.2/32"
    And show command "show isis route" in namespace "a1" should eventually contain "10.0.0.3/32"
    And show command "show isis route" in namespace "a2" should eventually contain "10.0.0.1/32"
    And show command "show isis route" in namespace "a2" should eventually contain "10.0.0.3/32"
    And show command "show isis route" in namespace "a3" should eventually contain "10.0.0.1/32"
    And show command "show isis route" in namespace "a3" should eventually contain "10.0.0.2/32"
    # Raise a1's priority above a3 so a1 takes over as DIS.
    When I apply config "a1-pri.yaml" to namespace "a1"
    And I wait 15 seconds
    # a2 must now point its adjacency at a1's pseudonode (Other -> Other
    # switch) — the bug left it stuck on 0000.0000.0003.* here.
    Then show command "show isis interface" in namespace "a2" should eventually contain "0000.0000.0001."
    And show command "show isis interface" in namespace "a3" should eventually contain "0000.0000.0001."
    # ... and every router STILL reaches every loopback. a2's route to
    # a1's loopback (10.0.0.1/32) is the one the Other -> Other bug dropped.
    And show command "show isis route" in namespace "a1" should eventually contain "10.0.0.2/32"
    And show command "show isis route" in namespace "a1" should eventually contain "10.0.0.3/32"
    And show command "show isis route" in namespace "a2" should eventually contain "10.0.0.1/32"
    And show command "show isis route" in namespace "a2" should eventually contain "10.0.0.3/32"
    And show command "show isis route" in namespace "a3" should eventually contain "10.0.0.1/32"
    And show command "show isis route" in namespace "a3" should eventually contain "10.0.0.2/32"

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
