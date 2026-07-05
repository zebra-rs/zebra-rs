@mirror_sid_node_base
@isis
Feature: IS-IS SRv6 Mirror SID egress NODE protection — stale-route retention
  TI-LFA and the egress-link redirect both need the protected egress to
  stay alive. This feature covers the other failure: the protected
  egress's whole NODE goes down. pea is a stub egress reachable only via
  the PLR pe1; peb (the protector) is reached directly over pe1-peb and
  advertises a Mirror SID (End.M) for pea's locator fcbb:bbbb:3::/48.

  While pea is up, pe1 routes to its locator over the pe1-pea adjacency
  and carries peb's Mirror SID as the egress-protection backup. When pea's
  node fails, that adjacency drops and pea's locator leaves the SPF — the
  diff would normally withdraw it, taking the repair with it. Mirror SID
  node-protection **stale-route retention** instead keeps the locator
  alive as a seg6 H.Encaps route to peb's Mirror SID, so traffic into the
  failed egress's locator is carried to the protector and the failover
  survives SPF reconvergence (not just the sub-second BFD window). When
  pea returns, its real locator route supersedes the retained one.

  ```
          pea (stub)            pea: protected egress (LOC3 fcbb:bbbb:3::/48)
         /                      peb: protector (LOC4), Mirror SID
   ... pe1 (PLR/ingress)             fcbb:bbbb:4:1:: for fcbb:bbbb:3::/48
         \
          peb --- ce2           pe1 reaches peb WITHOUT transiting pea
  ```
  The seg6 H.Encaps forwarding the retained route points at is exercised
  with live traffic by @mirror_sid_egress_link; here we validate that the
  locator route itself survives the node failure and is withdrawn on
  recovery.

  Scenario: Build topology and confirm IS-IS SRv6 + Mirror SID exchange
    Given a clean test environment
    When I create namespace "pe1"
    And I create namespace "pea"
    And I create namespace "peb"
    And I create namespace "ce2"
    And I connect namespace "pe1" interface "pe1-pea" to namespace "pea" interface "pea-pe1"
    And I connect namespace "pe1" interface "pe1-peb" to namespace "peb" interface "peb-pe1"
    And I connect namespace "peb" interface "peb-ce2" to namespace "ce2" interface "eth-b"
    And I add address "2001:db8:bc::2/64" to interface "eth-b" in namespace "ce2"
    And I start zebra-rs in namespace "pe1"
    And I start zebra-rs in namespace "pea"
    And I start zebra-rs in namespace "peb"
    And I apply config "pe1.yaml" to namespace "pe1"
    And I apply config "pea.yaml" to namespace "pea"
    And I apply config "peb.yaml" to namespace "peb"
    And I wait 20 seconds
    Then isis neighbor in namespace "pe1" at level 2 on interface "pe1-pea" should be up
    And isis neighbor in namespace "pe1" at level 2 on interface "pe1-peb" should be up
    # peb advertises the Mirror SID; pe1 receives it (the PLR's view).
    And show command "show isis egress-protection" in namespace "peb" should contain "fcbb:bbbb:3::/48"
    And show command "show isis egress-protection" in namespace "pe1" should contain "fcbb:bbbb:4:1::"

  Scenario: Steady state — pe1 routes to pea's locator over the direct adjacency
    Given the test topology exists
    # The locator is reached natively over the pe1-pea adjacency (the
    # link-local nexthop), not via the seg6 Mirror SID backup yet.
    Then kernel route "fcbb:bbbb:3::/48" in namespace "pe1" should eventually contain "dev pe1-pea"

  Scenario: Node failure — retention keeps the locator via the Mirror SID
    Given the test topology exists
    # Stop pea's daemon: the node fails. The pe1-pea adjacency (fast
    # hellos, 3 s hold) drops, pea's locator leaves pe1's SPF, and
    # retention reinstalls it as a seg6 H.Encaps route to peb's Mirror SID
    # over pe1-peb.
    When I stop zebra-rs in namespace "pea"
    Then kernel route "fcbb:bbbb:3::/48" in namespace "pe1" should eventually contain "seg6"
    And kernel route "fcbb:bbbb:3::/48" in namespace "pe1" should eventually contain "fcbb:bbbb:4:1::"

  Scenario: Recovery — pea returns and its real locator route supersedes
    Given the test topology exists
    When I start zebra-rs in namespace "pea"
    And I apply config "pea.yaml" to namespace "pea"
    # The native locator route (over pe1-pea) is best-path again and the
    # seg6 Mirror SID backup is demoted out of the FIB.
    Then kernel route "fcbb:bbbb:3::/48" in namespace "pe1" should eventually contain "dev pe1-pea"

  Scenario: Hold-down bounds the retention and withdraws the backup
    Given the test topology exists
    # Arm a short node-protection hold-down on the PLR. With pea up the
    # backup floats unselected, so this just sets the timer value.
    When I apply command "set router isis egress-protection hold-down 10" in namespace "pe1"
    And I wait 3 seconds
    # Fail pea's node again. The backup is promoted (seg6 to peb's Mirror
    # SID) while the hold-down counts...
    When I stop zebra-rs in namespace "pea"
    Then kernel route "fcbb:bbbb:3::/48" in namespace "pe1" should eventually contain "seg6"
    # ...then the hold-down fires and withdraws it, so the locator becomes
    # unreachable rather than masked toward the protector forever.
    Then kernel route "fcbb:bbbb:3::/48" in namespace "pe1" should eventually be gone

  Scenario: After the hold-down, a returning egress re-installs the backup
    Given the test topology exists
    When I start zebra-rs in namespace "pea"
    And I apply config "pea.yaml" to namespace "pea"
    # pea's native locator route is back and best-path again.
    Then kernel route "fcbb:bbbb:3::/48" in namespace "pe1" should eventually contain "dev pe1-pea"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "pe1"
    And I stop zebra-rs in namespace "pea"
    And I stop zebra-rs in namespace "peb"
    And I delete namespace "pe1"
    And I delete namespace "pea"
    And I delete namespace "peb"
    And I delete namespace "ce2"
    Then the test environment should be clean
