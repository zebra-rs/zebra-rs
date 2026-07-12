@isis_sr_dataplane_choice
@isis
Feature: IS-IS segment-routing mpls/srv6 are mutually exclusive (YANG choice)
  As a network operator
  I want `router isis segment-routing mpls` and `router isis
  segment-routing srv6` to be a YANG choice, so committing one
  dataplane implicitly deletes the other (RFC 7950 §7.9.3) — a single
  `set router isis segment-routing srv6 locator LOC1` migrates a
  running SR-MPLS node to SRv6 without a separate `delete`, and the
  implicit delete tears the old dataplane's forwarding state down
  exactly as an explicit one would.

  z1 and z2 run dual-stack IS-IS L2 over one point-to-point link, both
  starting on SR-MPLS (Prefix-SID indexes 100/200 -> labels
  16100/16200 against the default SRGB base 16000). z1 additionally
  pre-provisions the global SRv6 locator LOC1 (fcbb:bbbb:1::/48)
  without binding it to IS-IS. The feature flips z1's dataplane to
  SRv6 and back with one `set` each way and checks three layers every
  time:
  - config: `show running-config formal` holds exactly one dataplane
    case (and the unrelated global `segment-routing locator` block
    survives the sibling purge);
  - local forwarding: the MPLS ILM empties and the locator's End SID
    appears as a kernel seg6local route (then the reverse);
  - the peer: z2 stays on SR-MPLS throughout, and label 16100 leaves
    and re-enters its ILM as z1 stops/resumes advertising a
    Prefix-SID.

  Test Topology:
  ```
   z1 ──────────────── z2
   10.0.12.1/24        10.0.12.2/24
   2001:db8:0:12::1/64 2001:db8:0:12::2/64
   lo 10.0.0.1, 2001:db8::1, SID 100, LOC1 fcbb:bbbb:1::/48 (unbound)
   lo 10.0.0.2, 2001:db8::2, SID 200 (SR-MPLS for the whole feature)
  ```

  Scenario: Build the dual-stack SR-MPLS topology
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    Then ping from "z1" to "10.0.0.2" should eventually succeed
    And ping from "z1" to "2001:db8::2" should eventually succeed
    # Both nodes advertise a Prefix-SID: z1's ILM holds its own label
    # (16100, local pop) and z2's (16200, pop — adjacent PHP).
    And show command "show mpls ilm" in namespace "z1" should eventually contain "16100"
    And show command "show mpls ilm" in namespace "z1" should eventually contain "16200"
    And show command "show running-config formal" in namespace "z1" should contain "router isis segment-routing mpls"
    # The pre-provisioned locator is present but unbound — no SRv6
    # SIDs exist yet.
    And show command "show running-config formal" in namespace "z1" should contain "segment-routing locator LOC1 prefix fcbb:bbbb:1::/48"
    And show command "show segment-routing srv6 sid" in namespace "z1" should not contain "fcbb"

  Scenario: Setting srv6 implicitly deletes mpls and swaps the dataplane
    Given the test topology exists
    # No `delete router isis segment-routing mpls` anywhere — the
    # choice makes the set below carry the delete implicitly.
    When I apply command "set router isis segment-routing srv6 locator LOC1" in namespace "z1"
    # Config level: exactly one case remains, and the purge removed
    # only the sibling case — the global segment-routing block (same
    # node name, different parent) is untouched.
    Then show command "show running-config formal" in namespace "z1" should contain "router isis segment-routing srv6 locator LOC1"
    And show command "show running-config formal" in namespace "z1" should not contain "segment-routing mpls"
    And show command "show running-config formal" in namespace "z1" should contain "segment-routing locator LOC1 prefix fcbb:bbbb:1::/48"
    # Dataplane level: the locator's End SID installs as a seg6local
    # kernel route, and the SR-MPLS ILM is torn down by the implicit
    # delete — the commit dispatches it exactly like an explicit one.
    And show command "show segment-routing srv6 sid" in namespace "z1" should eventually contain "End"
    And kernel route "fcbb:bbbb:1::" in namespace "z1" should eventually contain "seg6local"
    And show command "show mpls ilm" in namespace "z1" should eventually not contain "16200"
    And mpls ilm in namespace "z1" should be empty
    # LSP level: z1 stopped advertising a Prefix-SID, so its label
    # leaves the SR-MPLS peer's ILM; the adjacency itself is
    # unaffected and both address families still forward.
    And show command "show mpls ilm" in namespace "z2" should eventually not contain "16100"
    And ping from "z1" to "10.0.0.2" should eventually succeed
    And ping from "z1" to "2001:db8::2" should succeed

  Scenario: Setting mpls implicitly deletes srv6 and restores the labels
    Given the test topology exists
    When I apply command "set router isis segment-routing mpls" in namespace "z1"
    # Config level: the srv6 case (locator binding included) is gone;
    # the global locator definition survives again.
    Then show command "show running-config formal" in namespace "z1" should contain "router isis segment-routing mpls"
    And show command "show running-config formal" in namespace "z1" should not contain "srv6"
    And show command "show running-config formal" in namespace "z1" should contain "segment-routing locator LOC1 prefix fcbb:bbbb:1::/48"
    # Dataplane level: labels come back, the End SID route goes.
    And show command "show mpls ilm" in namespace "z1" should eventually contain "16100"
    And show command "show mpls ilm" in namespace "z1" should eventually contain "16200"
    And kernel route "fcbb:bbbb:1::" in namespace "z1" should eventually be gone
    And show command "show segment-routing srv6 sid" in namespace "z1" should not contain "fcbb"
    # LSP level: z1 advertises its Prefix-SID again and the peer's ILM
    # relearns label 16100.
    And show command "show mpls ilm" in namespace "z2" should eventually contain "16100"
    And ping from "z1" to "10.0.0.2" should eventually succeed
    And ping from "z1" to "2001:db8::2" should succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
