@isis_flexalgo
@isis
Feature: IS-IS Flexible Algorithm with affinity-based topology constraints
  As a network operator running a global backbone (inspired by the Graphiant
  backbone topology), I want IS-IS Flex-Algo (RFC 9350) to confine traffic to
  specific regional sub-topologies so that data-sovereignty and compliance
  policies (HIPAA, GDPR) are enforced at the routing layer.

  Five zebra-rs instances form a two-region backbone.  Each link is tagged
  with one or more affinity names from the global /affinity-map table.
  Two custom algorithms restrict the SPF graph by excluding non-compliant
  link colors:

    Algo 128 (US-only / HIPAA): exclude-any [eu, transatlantic]
    Algo 129 (EU-only / GDPR):  exclude-any [transatlantic, us]

  The FAD (Flex-Algorithm Definition) for both algorithms is originated by
  the Chicago (ch) router; every other router participates without
  advertising a FAD.

  Topology (all links point-to-point; default metric 10):

    se (10.0.0.1)           ch (10.0.0.2)            ln (10.0.0.4)
    SID 16001    ---[us]--- SID 16002  ---[trans]--- SID 16004
                                 |                        |
                               [us]                     [eu]
                                 |                        |
                            va (10.0.0.3)           fr (10.0.0.5)
                            SID 16003    ---[trans]--- SID 16005

  Affinity map:
    us           bit 0   Links: se--ch, ch--va
    transatlantic bit 1  Links: ch--ln, va--fr
    eu           bit 2   Links: ln--fr

  Per-algo prefix-SIDs (SRGB base 16000):
    Node  Algo-0  Algo-128  Algo-129
    se      16001    16011    16021
    ch      16002    16012    16022
    va      16003    16013    16023
    ln      16004    16014    16024
    fr      16005    16015    16025

  Config files: se.yaml  ch.yaml  va.yaml  ln.yaml  fr.yaml

  Scenario: Build the Flex-Algo topology and confirm IS-IS adjacencies
    Given a clean test environment
    When I create namespace "se"
    And I create namespace "ch"
    And I create namespace "va"
    And I create namespace "ln"
    And I create namespace "fr"
    And I connect namespace "se" interface "se-ch" to namespace "ch" interface "ch-se"
    And I connect namespace "ch" interface "ch-va" to namespace "va" interface "va-ch"
    And I connect namespace "ch" interface "ch-ln" to namespace "ln" interface "ln-ch"
    And I connect namespace "va" interface "va-fr" to namespace "fr" interface "fr-va"
    And I connect namespace "ln" interface "ln-fr" to namespace "fr" interface "fr-ln"
    And I start zebra-rs in namespace "se"
    And I start zebra-rs in namespace "ch"
    And I start zebra-rs in namespace "va"
    And I start zebra-rs in namespace "ln"
    And I start zebra-rs in namespace "fr"
    And I apply config "se.yaml" to namespace "se"
    And I apply config "ch.yaml" to namespace "ch"
    And I apply config "va.yaml" to namespace "va"
    And I apply config "ln.yaml" to namespace "ln"
    And I apply config "fr.yaml" to namespace "fr"
    And I wait 15 seconds
    # se and ch are directly adjacent over se-ch
    Then ping from "se" to "192.168.1.2" should succeed
    # ch can reach ln's directly-connected interface via the transatlantic link
    And ping from "ch" to "192.168.1.10" should succeed

  Scenario: FAD advertisement is visible from the originating router
    Given the test topology exists
    # ch originates the FAD for both algos (advertise-definition: true).
    Then show command "show isis flex-algo" in namespace "ch" should contain "128"
    And show command "show isis flex-algo" in namespace "ch" should contain "129"
    # Verify the exclude-any constraints are encoded correctly.
    # BTreeSet ordering: eu < transatlantic, transatlantic < us
    And show command "show isis flex-algo" in namespace "ch" should contain "exclude-any=eu,transatlantic"
    And show command "show isis flex-algo" in namespace "ch" should contain "exclude-any=transatlantic,us"

  Scenario: FAD floods to non-originating routers
    Given the test topology exists
    # se participates in both algos but does not originate the FAD itself.
    # The peer FADs section of show isis flex-algo should list ch's FADs.
    Then show command "show isis flex-algo" in namespace "se" should contain "128"
    And show command "show isis flex-algo" in namespace "se" should contain "129"

  Scenario: Algo 128 (US-only) route table contains only US-region nodes
    Given the test topology exists
    # From se: ch (10.0.0.2) and va (10.0.0.3) are reachable via us-tagged
    # links only.  ln and fr require a transatlantic link which is excluded.
    Then show command "show isis flex-algo route algorithm 128" in namespace "se" should contain "10.0.0.2"
    And show command "show isis flex-algo route algorithm 128" in namespace "se" should contain "10.0.0.3"
    And show command "show isis flex-algo route algorithm 128" in namespace "se" should not contain "10.0.0.4"
    And show command "show isis flex-algo route algorithm 128" in namespace "se" should not contain "10.0.0.5"

  Scenario: Algo 129 (EU-only) route table contains only EU-region nodes
    Given the test topology exists
    # From ln: fr (10.0.0.5) is reachable via eu-tagged link only.
    # se, ch, and va require a transatlantic link which is excluded.
    Then show command "show isis flex-algo route algorithm 129" in namespace "ln" should contain "10.0.0.5"
    And show command "show isis flex-algo route algorithm 129" in namespace "ln" should not contain "10.0.0.1"
    And show command "show isis flex-algo route algorithm 129" in namespace "ln" should not contain "10.0.0.2"
    And show command "show isis flex-algo route algorithm 129" in namespace "ln" should not contain "10.0.0.3"

  Scenario: Default algo-0 topology has full-mesh connectivity
    Given the test topology exists
    # The default SPF (algo 0) uses all links; se can reach ln (10.0.0.4)
    # via the ch--ln transatlantic path.
    Then ping from "se" to "10.0.0.4" should succeed
    And ping from "ln" to "10.0.0.1" should succeed

  Scenario: Teardown Flex-Algo topology
    Given the test topology exists
    When I stop zebra-rs in namespace "se"
    And I stop zebra-rs in namespace "ch"
    And I stop zebra-rs in namespace "va"
    And I stop zebra-rs in namespace "ln"
    And I stop zebra-rs in namespace "fr"
    And I delete namespace "se"
    And I delete namespace "ch"
    And I delete namespace "va"
    And I delete namespace "ln"
    And I delete namespace "fr"
    Then the test environment should be clean
