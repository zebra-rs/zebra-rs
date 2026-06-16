@stamp_v6_te_metric
@isis
Feature: STAMP link-delay measurement over an IPv6-only IS-IS link
  As a network operator running delay-based traffic engineering on an
  IPv6 fabric, I want each P2P link's delay measured actively (STAMP,
  RFC 8762) and advertised by IS-IS (RFC 8570 link-delay sub-TLVs) even
  when the link carries no IPv4 — so dual-stack and v6-only links are
  measured the same way.

  Two zebra-rs instances share one IPv6-only P2P link (global addresses
  for routing, link-locals for the adjacency — no IPv4 anywhere on the
  measured interface). Both run IS-IS with `te-metric measurement`
  enabled (probe interval 100 ms, damping period 2 s). Because no shared
  IPv4 pair exists, the one STAMP session per link falls back to the
  IPv6 link-local pair (the same v4-preferred / v6-LL-fallback rule BFD
  uses), scoped by the link's ifindex. After the first damping period
  the measured values appear as "Min/Max Unidirectional Link Delay" in
  both LSDBs.

  OSPF is intentionally absent: OSPFv2 is IPv4-only on the wire and
  OSPFv3 has no TE-metric origination, so there is nowhere on the OSPF
  side to publish an IPv6 delay (see docs/design/stamp-ipv6-plan.md §1).

  Topology:

    st1                                    st2
      st1-st2  2001:db8:61::1/64 ---- 2001:db8:61::2/64  st2-st1
      lo 2001:db8:0:ff61::1/128            lo 2001:db8:0:ff61::2/128

  Config files: st1.yaml  st2.yaml

  Scenario: Build the IPv6-only measured topology
    Given a clean test environment
    When I create namespace "st1"
    And I create namespace "st2"
    And I connect namespace "st1" interface "st1-st2" to namespace "st2" interface "st2-st1"
    And I start zebra-rs in namespace "st1"
    And I start zebra-rs in namespace "st2"
    And I apply config "st1.yaml" to namespace "st1"
    And I apply config "st2.yaml" to namespace "st2"
    And I wait 10 seconds
    Then isis neighbor in namespace "st1" at level 2 on interface "st1-st2" should be up
    And ping from "st1" to "2001:db8:61::2" should succeed

  Scenario: A v6 link-local STAMP session forms and measures the link
    Given the test topology exists
    # No shared IPv4 pair on the link, so the session forms over the
    # peer's IPv6 link-local — the remote shows as an fe80:: address.
    Then show command "show stamp" in namespace "st1" should eventually contain "fe80:"
    And show command "show stamp" in namespace "st2" should eventually contain "fe80:"
    # Replies are coming back (sender state goes Active), so the peer's
    # implicit reflector is answering on the [::]:862 listener.
    And show command "show stamp" in namespace "st1" should eventually contain "Active"
    And show command "show stamp session" in namespace "st1" should eventually contain "Min delay"
    # Phase 1.5 rung 1: the kernel software RX timestamp (SO_TIMESTAMPING)
    # feeds T4 on the v6 path too — software stamps are stack-level, so
    # they're delivered on veth; once kernel-stamped replies flow the
    # kernel count leaves zero.
    And show command "show stamp statistics" in namespace "st1" should eventually not contain "T4 kernel timestamps: 0 ("

  Scenario: IS-IS advertises the measured IPv6-link delay
    Given the test topology exists
    # RFC 8570 sub-TLV rendered from the self-originated LSP — present
    # only once a measured export landed (no static te-metric anywhere).
    Then show command "show isis database detail" in namespace "st1" should eventually contain "Min/Max Unidirectional Link Delay"
    And show command "show isis database detail" in namespace "st2" should eventually contain "Min/Max Unidirectional Link Delay"

  # Pure P2P topology (no bridge): deleting each namespace destroys the
  # veth pair ends it holds, so only the daemons and namespaces need
  # teardown.
  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "st1"
    And I stop zebra-rs in namespace "st2"
    And I delete namespace "st1"
    And I delete namespace "st2"
    Then the test environment should be clean
