@isis_flex_srv6
Feature: IS-IS Flexible Algorithm over the SRv6 dataplane
  SRv6 sibling of @isis_flexalgo. Same five-node, two-region backbone and
  the same affinity-constrained algorithms, but the Flex-Algo dataplane is
  SRv6 (RFC 9352 §7.1): every node advertises a distinct per-algorithm
  SRv6 locator, so reaching a node "in algo N" is plain longest-prefix
  IPv6 to that node's algo-N locator computed over the algo-N constrained
  topology — no per-prefix SID is pushed for transit.

    Algo 128 (US-only):  exclude-any [eu, transatlantic]
    Algo 129 (EU-only):  exclude-any [transatlantic, us]

  Topology (all links point-to-point; default metric 10):

    se ---[us]--- ch ---[transatlantic]--- ln
                  |                          |
                [us]                       [eu]
                  |                          |
                  va ---[transatlantic]--- fr

  Per-node SRv6 locators (/48):
    Node  base(algo0)        algo-128            algo-129
    se    2001:db8:a000::    2001:db8:a128::     2001:db8:a129::
    ch    2001:db8:b000::    2001:db8:b128::     2001:db8:b129::
    va    2001:db8:c000::    2001:db8:c128::     2001:db8:c129::
    ln    2001:db8:d000::    2001:db8:d128::     2001:db8:d129::
    fr    2001:db8:e000::    2001:db8:e128::     2001:db8:e129::

  The FAD for both algorithms is originated by ch; every other router
  participates without advertising a FAD.

  Scenario: Build the SRv6 Flex-Algo topology and confirm IS-IS adjacencies
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
    # se and ch are directly adjacent over se-ch (algo-0 reachability).
    Then ping from "se" to "192.168.1.2" should succeed

  Scenario: Local per-algo SRv6 locators are visible on the originator
    Given the test topology exists
    # ch binds its own /48 per algorithm; both must resolve and carry a
    # node End SID.
    Then show command "show isis flex-algo" in namespace "ch" should contain "2001:db8:b128"
    And show command "show isis flex-algo" in namespace "ch" should contain "2001:db8:b129"

  Scenario: Per-algo SRv6 locators flood to non-originating routers
    Given the test topology exists
    # se learns ch's per-algo locators from ch's SRv6 Locator TLV 27.
    Then show command "show isis flex-algo" in namespace "se" should contain "2001:db8:b128"

  Scenario: Algo 128 (US-only) SRv6 routes confine to the US sub-topology
    Given the test topology exists
    # From se: ch (b128) and va (c128) are reachable over us-tagged links
    # only. ln and fr need a transatlantic link, which algo 128 excludes.
    Then show command "show isis flex-algo route algorithm 128" in namespace "se" should contain "2001:db8:b128"
    And show command "show isis flex-algo route algorithm 128" in namespace "se" should contain "2001:db8:c128"
    And show command "show isis flex-algo route algorithm 128" in namespace "se" should not contain "2001:db8:d128"
    And show command "show isis flex-algo route algorithm 128" in namespace "se" should not contain "2001:db8:e128"

  Scenario: Algo 129 (EU-only) SRv6 routes confine to the EU sub-topology
    Given the test topology exists
    # From ln: fr (e129) is reachable over the eu link only. se/ch/va all
    # require a transatlantic link, which algo 129 excludes.
    Then show command "show isis flex-algo route algorithm 129" in namespace "ln" should contain "2001:db8:e129"
    And show command "show isis flex-algo route algorithm 129" in namespace "ln" should not contain "2001:db8:a129"
    And show command "show isis flex-algo route algorithm 129" in namespace "ln" should not contain "2001:db8:b129"
    And show command "show isis flex-algo route algorithm 129" in namespace "ln" should not contain "2001:db8:c129"

  Scenario: Per-algo SRv6 locator routes install into the IPv6 FIB
    Given the test topology exists
    # The algo-128 locator route to ch is a real IPv6 route in se's RIB.
    Then show command "show ipv6 route" in namespace "se" should contain "2001:db8:b128"

  Scenario: Teardown SRv6 Flex-Algo topology
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
