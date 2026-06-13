@stamp_te_metric
Feature: STAMP link-delay measurement feeding IGP TE metrics
  As a network operator running delay-based traffic engineering, I want
  each P2P link's delay measured actively (STAMP, RFC 8762) and the
  damped min/max/avg values advertised by the IGPs — IS-IS RFC 8570 and
  OSPFv2 RFC 7471 link-delay sub-TLVs — without configuring static
  te-metric values per link.

  Two zebra-rs instances share one P2P link. Both run IS-IS and OSPFv2
  on it with `te-metric measurement` enabled (probe interval 100 ms,
  damping period 2 s — lab values; defaults are 1 s / 30 s). Each
  daemon's STAMP Session-Sender probes its neighbor's implicit
  Session-Reflector; both IGPs share the one measurement session per
  link (multi-client). After the first damping period the measured
  values appear as "Min/Max Unidirectional Link Delay" in both LSDBs
  (the OSPF Extended-Link Opaque LSA is gated on segment-routing mpls).

  Topology:

    st1 (10.61.0.1)                      st2 (10.61.0.2)
      st1-st2  192.168.61.1/30 ---- 192.168.61.2/30  st2-st1

  Config files: st1.yaml  st2.yaml

  Scenario: Build the measured topology
    Given a clean test environment
    When I create namespace "st1"
    And I create namespace "st2"
    And I connect namespace "st1" interface "st1-st2" to namespace "st2" interface "st2-st1"
    And I start zebra-rs in namespace "st1"
    And I start zebra-rs in namespace "st2"
    And I apply config "st1.yaml" to namespace "st1"
    And I apply config "st2.yaml" to namespace "st2"
    And I wait 10 seconds
    Then ping from "st1" to "192.168.61.2" should succeed

  Scenario: STAMP sessions form and measure the link
    Given the test topology exists
    # One shared session per direction, keyed by the link addresses.
    Then show command "show stamp" in namespace "st1" should eventually contain "192.168.61.2"
    And show command "show stamp" in namespace "st2" should eventually contain "192.168.61.1"
    # Replies are coming back (sender state goes Active), so the
    # implicit reflector on the peer is answering.
    And show command "show stamp" in namespace "st1" should eventually contain "Active"
    And show command "show stamp session" in namespace "st1" should eventually contain "Min delay"

  Scenario: IS-IS advertises the measured link delay
    Given the test topology exists
    # RFC 8570 sub-TLV 34 rendered from the self-originated LSP — only
    # present once a measured export landed (no static te-metric is
    # configured anywhere in this feature).
    Then show command "show isis database detail" in namespace "st1" should eventually contain "Min/Max Unidirectional Link Delay"
    And show command "show isis database detail" in namespace "st2" should eventually contain "Min/Max Unidirectional Link Delay"

  Scenario: OSPFv2 advertises the measured link delay
    Given the test topology exists
    # RFC 7471 sub-TLV 28 inside the Extended-Link Opaque LSA's ASLA.
    Then show command "show ospf database detail" in namespace "st1" should eventually contain "Min/Max Unidirectional Link Delay"
    And show command "show ospf database detail" in namespace "st2" should eventually contain "Min/Max Unidirectional Link Delay"

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
