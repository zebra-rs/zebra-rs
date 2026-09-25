@isis_flexalgo_link_loss
Feature: IS-IS Flex-Algo prunes links whose measured loss exceeds the definition's maximum
  As a network operator, I want a Flexible Algorithm that avoids lossy
  links: its definition carries a maximum link loss
  (draft-ietf-lsr-flex-algo-link-loss, FAD sub-TLV 252), and every router
  computing the algorithm prunes each link whose advertised loss exceeds
  it, while algorithm 0 keeps using the link.

  ce advertises algorithm 128 with `exclude-max-link-loss 5`. STAMP
  measures the ce–n1 link with 100 ms probes and a 30 s loss interval,
  as the stamp_loss feature does, and advertises its loss. ce–n2 and
  n2–n1 are not measured, advertise no loss, and so are never pruned for
  it.

    ce (10.0.0.1) ---- n1 (10.0.0.2)      all metrics 10
        \             /
         n2 (10.0.0.3)

  Loss is injected as in the stamp_loss feature: an nftables rule on n1 drops every
  10th probe ce sends it, which ce measures as 10 % round-trip loss and
  advertises on ce→n1 only.

  Design: docs/design/flex-algo-link-loss.md (PR 2).

  Scenario: Build the triangle
    Given a clean test environment
    When I create namespace "ce"
    And I create namespace "n1"
    And I create namespace "n2"
    And I connect namespace "ce" interface "ce-n1" to namespace "n1" interface "n1-ce"
    And I connect namespace "ce" interface "ce-n2" to namespace "n2" interface "n2-ce"
    And I connect namespace "n2" interface "n2-n1" to namespace "n1" interface "n1-n2"
    And I start zebra-rs in namespace "ce"
    And I start zebra-rs in namespace "n1"
    And I start zebra-rs in namespace "n2"
    And I apply config "ce.yaml" to namespace "ce"
    And I apply config "n1.yaml" to namespace "n1"
    And I apply config "n2.yaml" to namespace "n2"
    And I wait 10 seconds
    Then ping from "ce" to "192.168.70.2" should succeed
    And show command "show stamp" in namespace "ce" should eventually contain "Active"

  Scenario: The definition carries the maximum link loss
    Given the test topology exists
    # 5 % is 1666666.67 RFC 8570 units, advertised rounded to nearest.
    Then show command "show isis flex-algo" in namespace "n1" should eventually contain "definition from ce (0000.0000.0001), priority 128, max link loss 5.000001% (1666667); participating"
    And show command "show isis flex-algo" in namespace "n2" should eventually contain "max link loss 5.000001% (1666667); participating"
    And show command "show isis database detail" in namespace "n2" should contain "FAD Exclude Max Link Loss: 5.000001% (1666667)"
    And show command "show isis flex-algo" in namespace "ce" should contain "max-link-loss=5.000000%(1666667)"
    # The wire caps loss at 50.331642 %; the commit refuses more.
    And applying command "set router isis flex-algo 128 exclude-max-link-loss 50.331643" in namespace "ce" should be rejected with "0 to 50.331642 percent"
    And show command "show running-config formal" in namespace "ce" should contain "exclude-max-link-loss 5"
    And show command "show running-config formal" in namespace "ce" should not contain "50.331643"

  Scenario: A clean link stays in the algorithm
    Given the test topology exists
    # Precondition for the pruning below: with no loss above 5 %, algorithm
    # 128 reaches n1 over the direct link, next hop 192.168.70.2.
    Then show command "show isis flex-algo route algorithm 128" in namespace "ce" should eventually contain "192.168.70.2"
    And show command "show isis flex-algo 128 graph" in namespace "ce" should not contain "Pruned links"

  Scenario: A lossy link is pruned from the algorithm but kept in algorithm 0
    Given the test topology exists
    When I drop every 10th STAMP probe arriving in namespace "n1"
    # ce advertises about 10 % on ce→n1 within two loss windows.
    Then show command "show isis flex-algo 128 graph" in namespace "ce" should contain "ce -> n1: link loss" within 120 seconds
    # Every router prunes it from ce's LSP, not just ce from its own
    # measurement.
    And show command "show isis flex-algo 128 graph" in namespace "n2" should eventually contain "ce -> n1: link loss"
    And show command "show isis flex-algo 128 graph" in namespace "n2" should contain "exceeds 5.000001% (1666667)"
    # No algorithm-128 route leaves ce over the pruned link; n1 is
    # reached through n2.
    And show command "show isis flex-algo route algorithm 128" in namespace "ce" should eventually not contain "192.168.70.2"
    And show command "show isis flex-algo route algorithm 128" in namespace "ce" should contain "10.0.0.2/32"
    # Algorithm 0 is unconstrained and keeps the direct link.
    And show command "show isis route" in namespace "ce" should contain "192.168.70.2"
    # Unmeasured links advertise no loss and are kept.
    And show command "show isis flex-algo 128 graph" in namespace "n2" should not contain "ce -> n2"
    And show command "show isis flex-algo 128 graph" in namespace "n2" should not contain "n2 -> n1"

  Scenario: The link returns once its loss falls back under the maximum
    Given the test topology exists
    When I stop dropping STAMP probes in namespace "n1"
    Then show command "show isis flex-algo route algorithm 128" in namespace "ce" should contain "192.168.70.2" within 150 seconds
    And show command "show isis flex-algo 128 graph" in namespace "n2" should eventually not contain "Pruned links"

  Scenario: Teardown
    Given the test topology exists
    When I stop zebra-rs in namespace "ce"
    And I stop zebra-rs in namespace "n1"
    And I stop zebra-rs in namespace "n2"
    And I delete namespace "ce"
    And I delete namespace "n1"
    And I delete namespace "n2"
    Then the test environment should be clean
