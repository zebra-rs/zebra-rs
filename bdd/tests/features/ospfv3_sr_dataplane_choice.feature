@ospfv3_sr_dataplane_choice
@ospf
Feature: OSPFv3 segment-routing mpls/srv6 are mutually exclusive (YANG choice)
  As a network operator
  I want `router ospfv3 segment-routing mpls` and `router ospfv3
  segment-routing srv6` to be a YANG choice, so committing one
  dataplane implicitly deletes the other (RFC 7950 §7.9.3) — a single
  `set router ospfv3 segment-routing srv6 locator LOC1` migrates a
  running RFC 8666 SR-MPLS node to RFC 9513 SRv6 without a separate
  `delete`, and the implicit delete tears the old dataplane's
  forwarding state down exactly as an explicit one would.

  This is the OSPFv3 sibling of @isis_sr_dataplane_choice — the choice
  enforcement is the same generic candidate-store purge, but the
  daemon-side effects it must drive are OSPFv3's own: the Prefix-SID
  sub-TLVs leave the E-LSAs and the ILM empties, while the SRv6
  Locator LSA is originated and the locator's End SID installs as a
  kernel seg6local route.

  z1 and z2 run OSPFv3 area 0 over one point-to-point link, both
  starting on SR-MPLS (Prefix-SID indexes 100/200 -> labels
  16100/16200 against the default SRGB base 16000). z1 additionally
  pre-provisions the global SRv6 locator LOC1 (fcbb:bbbb:1::/48,
  classic full-length SIDs) without binding it to OSPFv3. The feature
  flips z1's dataplane to SRv6 and back with one `set` each way and
  checks three layers every time:
  - config: `show running-config formal` holds exactly one dataplane
    case (and the unrelated global `segment-routing locator` block
    survives the sibling purge);
  - local forwarding: the MPLS ILM empties and the locator's End SID
    appears as a kernel seg6local route (then the reverse);
  - the peer: z2 stays on SR-MPLS throughout; label 16100 leaves and
    re-enters its ILM, and the SRv6 Locator LSA appears in and is
    flushed from its database as z1 switches over and back.

  Test Topology:
  ```
   z1 ──────────────── z2
   2001:db8:12::1/64   2001:db8:12::2/64
   lo 2001:db8::1, SID 100, LOC1 fcbb:bbbb:1::/48 (unbound)
   lo 2001:db8::2, SID 200 (SR-MPLS for the whole feature)
  ```

  Scenario: Build the OSPFv3 SR-MPLS topology
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z1-z2" to namespace "z2" interface "z2-z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 10 seconds
    Then ping from "z1" to "2001:db8::2" should eventually succeed
    # Both nodes advertise a Prefix-SID: z1's ILM holds its own label
    # (16100, local pop) and z2's (16200, pop — adjacent PHP).
    And show command "show mpls ilm" in namespace "z1" should eventually contain "16100"
    And show command "show mpls ilm" in namespace "z1" should eventually contain "16200"
    And show command "show running-config formal" in namespace "z1" should contain "router ospfv3 segment-routing mpls"
    # The pre-provisioned locator is present but unbound — no SRv6
    # SIDs exist and no Locator LSA is originated yet.
    And show command "show running-config formal" in namespace "z1" should contain "segment-routing locator LOC1 prefix fcbb:bbbb:1::/48"
    And show command "show segment-routing srv6 sid" in namespace "z1" should not contain "fcbb"
    And show command "show ospfv3 database" in namespace "z2" should not contain "SRv6-Locator-LSA"

  Scenario: Setting srv6 implicitly deletes mpls and swaps the dataplane
    Given the test topology exists
    # No `delete router ospfv3 segment-routing mpls` anywhere — the
    # choice makes the set below carry the delete implicitly.
    When I apply command "set router ospfv3 segment-routing srv6 locator LOC1" in namespace "z1"
    # Config level: exactly one case remains, and the purge removed
    # only the sibling case — the global segment-routing block (same
    # node name, different parent) is untouched.
    Then show command "show running-config formal" in namespace "z1" should contain "router ospfv3 segment-routing srv6 locator LOC1"
    And show command "show running-config formal" in namespace "z1" should not contain "segment-routing mpls"
    And show command "show running-config formal" in namespace "z1" should contain "segment-routing locator LOC1 prefix fcbb:bbbb:1::/48"
    # Dataplane level: the locator's End SID installs as a seg6local
    # kernel route (classic full-length SID -> /128 at the locator
    # base), and the SR-MPLS ILM is torn down by the implicit delete.
    And show command "show segment-routing srv6 sid" in namespace "z1" should eventually contain "End"
    And show command "show segment-routing srv6 sid" in namespace "z1" should contain "ospfv3"
    And kernel route "fcbb:bbbb:1::" in namespace "z1" should eventually contain "seg6local"
    And show command "show mpls ilm" in namespace "z1" should eventually not contain "16200"
    And mpls ilm in namespace "z1" should be empty
    # LSA level: z1 originates the SRv6 Locator LSA and stops
    # advertising a Prefix-SID, so its label leaves the SR-MPLS peer's
    # ILM; the adjacency itself is unaffected and plain v6 forwarding
    # continues.
    And show command "show ospfv3 database" in namespace "z2" should eventually contain "SRv6-Locator-LSA"
    And show command "show mpls ilm" in namespace "z2" should eventually not contain "16100"
    And ping from "z1" to "2001:db8::2" should eventually succeed

  Scenario: Setting mpls implicitly deletes srv6 and restores the labels
    Given the test topology exists
    When I apply command "set router ospfv3 segment-routing mpls" in namespace "z1"
    # Config level: the srv6 case (locator binding included) is gone;
    # the global locator definition survives again.
    Then show command "show running-config formal" in namespace "z1" should contain "router ospfv3 segment-routing mpls"
    And show command "show running-config formal" in namespace "z1" should not contain "srv6"
    And show command "show running-config formal" in namespace "z1" should contain "segment-routing locator LOC1 prefix fcbb:bbbb:1::/48"
    # Dataplane level: labels come back, the End SID route goes.
    And show command "show mpls ilm" in namespace "z1" should eventually contain "16100"
    And show command "show mpls ilm" in namespace "z1" should eventually contain "16200"
    And kernel route "fcbb:bbbb:1::" in namespace "z1" should eventually be gone
    And show command "show segment-routing srv6 sid" in namespace "z1" should not contain "fcbb"
    # LSA level: z1 advertises its Prefix-SID again and flushes the
    # SRv6 Locator LSA; the peer's ILM relearns label 16100 and its
    # database drops the locator.
    And show command "show mpls ilm" in namespace "z2" should eventually contain "16100"
    And show command "show ospfv3 database" in namespace "z2" should eventually not contain "SRv6-Locator-LSA"
    And ping from "z1" to "2001:db8::2" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
