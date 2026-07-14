@bgp_sr_policy_bsid_steering
Feature: BGP SR Policy Binding-SID steering mode (RFC 9256 §8.5)
  An operator selects how colour-matched service routes are steered onto
  an SR Policy: the whole SID list imposed inline (`segment-list`, the
  historical default) or just the policy's Binding SID (`binding-sid`,
  which the BSID's own forwarding entry — an SR-MPLS ILM or an SRv6
  End.B6.Encaps SID — expands). This feature validates the new
  `steering-mode` config surface end to end in a running daemon: the YANG
  parses, the callback stages the mode onto the Loc-RIB SR Policy DB, and
  `show bgp sr-policy` reflects it (both values). The steering *decision*
  logic — BSID selection, the RFC 9256 §8.8.1 CO-bit endpoint fallback,
  and the SR-MPLS ILM-installed gate — is covered by the unit tests in
  `zebra-rs/src/bgp/sr_policy.rs`.

  Topology:
  ```
   crs1 [ zebra-rs headend ]
        router bgp 65001
          sr-policy
            steering-mode binding-sid   (toggled to segment-list below)
            policy GREEN color 100 endpoint 10.0.0.9 binding-sid-label 16100
  ```

  Scenario: The binding-sid steering mode is configured and shown
    Given a clean test environment
    When I create namespace "crs1"
    And I start zebra-rs in namespace "crs1"
    And I apply config "crs1.yaml" to namespace "crs1"
    # The new `steering-mode` leaf reached the Loc-RIB SR Policy DB and the
    # show path renders it.
    Then show command "show bgp sr-policy" in namespace "crs1" should eventually contain "Steering mode: binding-sid"

  Scenario: Flipping the mode back to segment-list takes effect live
    Given the test topology exists
    When I apply command "set router bgp sr-policy steering-mode segment-list" in namespace "crs1"
    Then show command "show bgp sr-policy" in namespace "crs1" should eventually contain "Steering mode: segment-list"

  Scenario: Deleting the mode restores the segment-list default
    Given the test topology exists
    When I apply command "set router bgp sr-policy steering-mode binding-sid" in namespace "crs1"
    Then show command "show bgp sr-policy" in namespace "crs1" should eventually contain "Steering mode: binding-sid"
    When I apply command "delete router bgp sr-policy steering-mode binding-sid" in namespace "crs1"
    Then show command "show bgp sr-policy" in namespace "crs1" should eventually contain "Steering mode: segment-list"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "crs1"
    And I delete namespace "crs1"
    Then the test environment should be clean
