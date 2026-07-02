@serial
@bgp_fast_external_failover
Feature: BGP fast-external-failover (immediate eBGP reset on link down)
  As a network operator
  I want a directly connected eBGP session to be reset the moment its
  interface goes down (IOS-XR `bgp fast-external-fallover`, on by
  default), instead of waiting out the 180-second hold timer — and I
  want `fast-external-failover false` to restore hold-timer-only
  detection.

  Test Topology (direct P2P veth, single-hop eBGP):
  ```
   ┌─────────┐   10.107.0.0/24   ┌─────────┐
   │   z1    │ i1─────────────i1 │   z2    │
   │ AS65001 │                   │ AS65002 │
   │  .0.1   │                   │  .0.2   │
   └─────────┘                   └─────────┘
  ```

  Downing z1's veth end drops carrier on BOTH ends (a veth pair has no
  independent carrier), so each router sees its own LinkDown and both
  must reset. The default hold time is 180s and the session-state polls
  budget 30s, so every "eventually not Established" assertion passing
  is itself proof the reset did not come from the hold timer.

  Config files:
  - z1.yaml / z2.yaml: direct eBGP over the veth, one originated
    prefix each, fast-external-failover left at its default (enabled).
    The disabled case is applied at runtime with
    `set router bgp global fast-external-failover false`.

  Scenario: Setup direct eBGP topology and establish the session
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "i1" to namespace "z2" interface "i1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 10 seconds for BGP to operate
    Then BGP session in "z1" to "10.107.0.2" should eventually be "Established"
    And BGP session in "z2" to "10.107.0.1" should eventually be "Established"
    And BGP route in "z2" has "10.1.1.1/32"
    And BGP route in "z1" has "10.2.2.2/32"

  Scenario: Link down resets the session immediately (default enabled)
    Given the test topology exists
    When I make namespace "z1" interface "i1" down
    Then BGP session in "z1" to "10.107.0.2" should eventually not be "Established"
    And BGP session in "z2" to "10.107.0.1" should eventually not be "Established"
    And the zebra-rs log in namespace "z1" should contain "fast-external-failover: interface down"
    And the zebra-rs log in namespace "z2" should contain "fast-external-failover: interface down"
    And show command "show bgp neighbor" in namespace "z1" should contain "due to Interface down"

  Scenario: Link up re-establishes the session without waiting out connect-retry
    Given the test topology exists
    When I make namespace "z1" interface "i1" up
    Then BGP session in "z1" to "10.107.0.2" should eventually be "Established"
    And BGP session in "z2" to "10.107.0.1" should eventually be "Established"

  Scenario: Disabling fast-external-failover does not bounce the session
    Given the test topology exists
    When I apply command "set router bgp global fast-external-failover false" in namespace "z1"
    And I apply command "set router bgp global fast-external-failover false" in namespace "z2"
    And I wait 2 seconds
    Then BGP session in "z1" to "10.107.0.2" should be "Established"
    And BGP session in "z2" to "10.107.0.1" should be "Established"

  Scenario: With the knob disabled, link down leaves the session to the hold timer
    Given the test topology exists
    When I make namespace "z1" interface "i1" down
    And I wait 10 seconds
    # Hold time is 180s and TCP retransmits silently on a dead link, so
    # with the knob off the session must still be up 10s after the cut —
    # this is the assertion that discriminates the feature from ambient
    # TCP/hold-timer behaviour.
    Then BGP session in "z1" to "10.107.0.2" should be "Established"
    And BGP session in "z2" to "10.107.0.1" should be "Established"

  # Pure P2P topology (no bridge): deleting each namespace destroys the
  # veth pair ends it holds, so only the daemons and namespaces need
  # teardown.
  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
