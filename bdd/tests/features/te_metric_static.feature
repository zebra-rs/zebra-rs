@te_metric_static
@isis
Feature: Statically configured TE link metrics in all three IGPs
  As an operator who knows a link's characteristics without measuring
  them — a leased circuit with a contracted delay, a lab link being
  pinned for a test — I want the configured RFC 8570 / RFC 7471 values
  advertised verbatim by whichever IGP carries the link.

  Two zebra-rs instances share one dual-stack P2P link and run all three
  IGPs over it. Each protocol is given a *different* set of te-metric
  values, so every assertion names a number only one of them could have
  produced: a value leaking between the three protocols' link configs,
  or a builder reading the wrong field, shows up as a wrong number
  rather than as silence.

    IS-IS   avg 1000us  min/max  900/1200us  var 50us  loss 333
    OSPFv2  avg 2000us  min/max 1800/2400us  var 60us  loss 666
    OSPFv3  avg 3000us  min/max 2700/3600us  var 70us  loss 999

  This is the counterpart to stamp_te_metric and stamp_v6_te_metric,
  which cover the measured path. Those can only assert that a delay
  field is present, because the measured value varies run to run; here
  the values are known, so the encodings are checked exactly — including
  the RFC 8570 §4.4 loss unit of 0.000003 %, where 333 is 0.000999 %.

  Both OSPF versions need segment-routing enabled: their TE metrics ride
  LSAs (the Extended-Link Opaque LSA and the E-Router-LSA) that are only
  originated when SR is on.

  Topology:

    tm1                                    tm2
      tm1-tm2  192.168.72.1/30 ---- 192.168.72.2/30  tm2-tm1
               2001:db8:72::1/64 -- 2001:db8:72::2/64

  Config files: tm1.yaml  tm2.yaml

  Scenario: Build the dual-stack topology
    Given a clean test environment
    When I create namespace "tm1"
    And I create namespace "tm2"
    And I connect namespace "tm1" interface "tm1-tm2" to namespace "tm2" interface "tm2-tm1"
    And I start zebra-rs in namespace "tm1"
    And I start zebra-rs in namespace "tm2"
    And I apply config "tm1.yaml" to namespace "tm1"
    And I apply config "tm2.yaml" to namespace "tm2"
    And I wait 10 seconds
    Then ping from "tm1" to "192.168.72.2" should succeed

  Scenario: All three IGPs form adjacencies
    Given the test topology exists
    Then show command "show isis neighbor" in namespace "tm1" should eventually contain "tm2"
    And show command "show ospf neighbor" in namespace "tm1" should eventually contain "Full"
    And show command "show ospfv3 neighbor" in namespace "tm1" should eventually contain "Full"

  Scenario: IS-IS advertises its configured values verbatim
    Given the test topology exists
    # RFC 8570 sub-TLVs 33/34/35/36 on the Extended IS Reachability TLV.
    # Asserted on tm2 so the values are ones it parsed off the wire.
    Then show command "show isis database detail" in namespace "tm2" should eventually contain "Unidirectional Link Delay: 1000 us"
    And show command "show isis database detail" in namespace "tm2" should eventually contain "Min/Max Unidirectional Link Delay: min 900 us, max 1200 us"
    And show command "show isis database detail" in namespace "tm2" should eventually contain "Unidirectional Delay Variation: 50 us"
    And show command "show isis database detail" in namespace "tm2" should eventually contain "Unidirectional Link Loss: 0.000999%"

  Scenario: OSPFv2 advertises its own, different values
    Given the test topology exists
    # RFC 7471 sub-TLVs 27-30 inside the Extended-Link Opaque LSA's ASLA.
    Then show command "show ospf database detail" in namespace "tm2" should eventually contain "Unidirectional Link Delay: 2000 usec"
    And show command "show ospf database detail" in namespace "tm2" should eventually contain "Min/Max Unidirectional Link Delay: 1800/2400 usec"
    And show command "show ospf database detail" in namespace "tm2" should eventually contain "Unidirectional Delay Variation: 60 usec"
    And show command "show ospf database detail" in namespace "tm2" should eventually contain "Unidirectional Link Loss: 0.001998 %"
    # IS-IS's numbers must not appear in an OSPF LSA.
    And show command "show ospf database detail" in namespace "tm2" should eventually not contain "1800/1200"

  Scenario: OSPFv3 advertises its own values at the OSPFv3 code points
    Given the test topology exists
    # Same RFC 7471 encodings, but OSPFv3 sub-TLVs 13-16 from the
    # Extended-LSA registry, inside the E-Router-LSA's ASLA.
    Then show command "show ospfv3 database detail" in namespace "tm2" should eventually contain "Unidirectional Link Delay: 3000 usec"
    And show command "show ospfv3 database detail" in namespace "tm2" should eventually contain "Min/Max Unidirectional Link Delay: 2700/3600 usec"
    And show command "show ospfv3 database detail" in namespace "tm2" should eventually contain "Unidirectional Delay Variation: 70 usec"
    And show command "show ospfv3 database detail" in namespace "tm2" should eventually contain "Unidirectional Link Loss: 0.002997 %"
    # OSPFv2's values belong to a different protocol's link config.
    And show command "show ospfv3 database detail" in namespace "tm2" should eventually not contain "1800/2400"

  Scenario: Static values are never advertised as anomalous
    Given the test topology exists
    # A pinned value is the operator's assertion, not an observation, so
    # there is no threshold crossing to report against it (RFC 8570
    # §4.1). No measurement is running here at all.
    Then show command "show isis database detail" in namespace "tm2" should eventually not contain "us (A)"
    And show command "show ospf database detail" in namespace "tm2" should eventually not contain "(Anomalous)"
    And show command "show ospfv3 database detail" in namespace "tm2" should eventually not contain "(Anomalous)"

  Scenario: A pinned bound survives measurement being switched on
    Given the test topology exists
    # Turn IS-IS measurement on with every field still pinned. The
    # measured delay on a veth is tens of microseconds, so if the merge
    # let the measurement win, 900/1200 would be replaced by something
    # far smaller. Every field is static here, so every field must
    # survive — the per-field nature of the merge is covered by the
    # `merged_over` unit tests, which can construct a half-pinned link
    # that no config file can express in one commit.
    When I apply command "set router isis interface tm1-tm2 te-metric measurement enabled true" in namespace "tm1"
    And I apply command "set router isis interface tm1-tm2 te-metric measurement interval 100" in namespace "tm1"
    And I apply command "set router isis interface tm1-tm2 te-metric measurement damping-period 2" in namespace "tm1"
    And I apply command "set router isis interface tm2-tm1 te-metric measurement enabled true" in namespace "tm2"
    And I apply command "set router isis interface tm2-tm1 te-metric measurement interval 100" in namespace "tm2"
    And I apply command "set router isis interface tm2-tm1 te-metric measurement damping-period 2" in namespace "tm2"
    And I wait 8 seconds
    Then show command "show stamp" in namespace "tm1" should eventually contain "Active"
    And show command "show isis database detail" in namespace "tm2" should eventually contain "Min/Max Unidirectional Link Delay: min 900 us, max 1200 us"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "tm1"
    And I stop zebra-rs in namespace "tm2"
    And I delete namespace "tm1"
    And I delete namespace "tm2"
    Then the test environment should be clean
