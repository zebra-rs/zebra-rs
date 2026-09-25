@stamp_loss
Feature: Measured link loss advertised by IS-IS and OSPF
  As a network operator running loss-aware traffic engineering, I want
  each P2P link's probe loss measured on its STAMP session and
  advertised as the RFC 8570 / RFC 7471 unidirectional link-loss
  sub-TLV, on by default wherever measurement is enabled.

  Two zebra-rs instances share one P2P link, running IS-IS and OSPFv2
  with `te-metric measurement` enabled: 100 ms probes (300 per 30 s loss
  bucket), and a 30 s loss interval instead of the 120 s default so the
  window fills quickly. `loss enabled` is deliberately left unset: every
  advertisement here comes from the default.

  Both routers' LSPs are in each database, and sl2's own link stays
  clean throughout, so a database assertion can only speak for sl1 where
  sl2's value cannot match: the 10 % range, or "never the cap". sl1's own
  advertisement is asserted on its `show stamp session` subscriber lines.

  Loss is injected deterministically. An nftables rule on the reflecting
  side drops exactly every Nth probe (`numgen inc mod N`), where netem's
  random loss would make a percentage assertion flaky. The advertised
  value is still a ratio of probe counts that moves slightly with where
  bucket boundaries fall, so values are asserted as ranges.

  Design: docs/design/stamp-measured-loss.md (PR 2 of 4).

  Topology:

    sl1 (10.64.0.1)                      sl2 (10.64.0.2)
      sl1-sl2  192.168.62.1/30 ---- 192.168.62.2/30  sl2-sl1

  Config files: sl1.yaml  sl2.yaml

  Scenario: Build the measured topology
    Given a clean test environment
    When I create namespace "sl1"
    And I create namespace "sl2"
    And I connect namespace "sl1" interface "sl1-sl2" to namespace "sl2" interface "sl2-sl1"
    And I start zebra-rs in namespace "sl1"
    And I start zebra-rs in namespace "sl2"
    And I apply config "sl1.yaml" to namespace "sl1"
    And I apply config "sl2.yaml" to namespace "sl2"
    And I wait 10 seconds
    Then ping from "sl1" to "192.168.62.2" should succeed
    And show command "show stamp" in namespace "sl1" should eventually contain "Active"
    And show command "show stamp" in namespace "sl2" should eventually contain "Active"

  Scenario: Loss is advertised by default on a clean link
    Given the test topology exists
    # The first trusted window closes 30 s after the session starts.
    # Probes sent before the peer's session registered its reflector are
    # lost, so the first value may be a fraction of a percent; below the
    # 1.0-point minimum change it is not re-advertised, hence the range.
    When I wait 30 seconds
    Then show command "show stamp session" in namespace "sl1" should eventually contain "isis: anomaly-threshold none"
    And show command "show stamp session" in namespace "sl1" should eventually contain "loss: advertised 0."
    And show command "show isis database detail" in namespace "sl2" should eventually show link loss between 0.0 and 1.0 percent
    And show command "show ospf database detail" in namespace "sl2" should eventually show link loss between 0.0 and 1.0 percent

  Scenario: A loss setting STAMP would refuse fails the commit
    Given the test topology exists
    # PR 2 review: YANG cannot express the 30 s step or bound a decimal64,
    # and a protocol's callback cannot reject a value, so a refused value
    # used to reach the running config while STAMP kept its previous
    # setting. The commit now checks these leaves before dispatch.
    Then applying command "set router isis interface sl1-sl2 te-metric measurement loss interval 45" in namespace "sl1" should be rejected with "must be a multiple of 30 seconds"
    And applying command "set router ospf area 0.0.0.0 interface sl1-sl2 te-metric measurement loss minimum-change 100.5" in namespace "sl1" should be rejected with "0 to 100 percent"
    And applying command "set router isis interface sl1-sl2 te-metric measurement loss accelerated-threshold 1.0000001" in namespace "sl1" should be rejected with "at most 6 decimal places"
    # The positive control shows the leaves render in this form, so the
    # "not contain" checks after it cannot pass vacuously.
    And show command "show running-config formal" in namespace "sl1" should contain "te-metric measurement loss interval 30"
    And show command "show running-config formal" in namespace "sl1" should not contain "loss interval 45"
    And show command "show running-config formal" in namespace "sl1" should not contain "minimum-change"
    And show command "show running-config formal" in namespace "sl1" should not contain "accelerated-threshold"

  Scenario: A 10 percent probe loss is advertised by both IGPs
    Given the test topology exists
    # Dropping every 10th probe sl1 sends to sl2 is 10 % round-trip loss
    # on sl1's session, advertised in sl1's LSP. Two windows at most: the
    # one the drop started in, then a full one.
    When I drop every 10th STAMP probe arriving in namespace "sl2"
    And I wait 20 seconds
    Then show command "show isis database detail" in namespace "sl2" should eventually show link loss between 9.0 and 11.0 percent
    And show command "show ospf database detail" in namespace "sl2" should eventually show link loss between 9.0 and 11.0 percent
    And show command "show stamp session" in namespace "sl1" should eventually contain "loss: advertised"

  Scenario: Crossing the loss anomaly bound sets the A bit, and recovery clears it
    Given the test topology exists
    # Design D7. The previous scenario's 10 % drop is still in place.
    # IS-IS on sl1 gets a 5 % anomaly bound and a 1 % reuse bound; OSPF
    # gets none yet. Both advertise the same 10 %, and only IS-IS's
    # carries the A bit: the bounds are each IGP's own (D10). sl2's own
    # link has no bounds, so any A bit in sl2's databases is sl1's.
    When I apply command "set router isis interface sl1-sl2 te-metric measurement loss anomaly-threshold 5" in namespace "sl1"
    And I apply command "set router isis interface sl1-sl2 te-metric measurement loss reuse-threshold 1" in namespace "sl1"
    Then show command "show isis database detail" in namespace "sl2" should eventually contain "% (A)"
    And show command "show stamp session" in namespace "sl1" should eventually contain "% (A) (interval 30s"
    And show command "show stamp session" in namespace "sl1" should contain ", anomaly "
    And show command "show ospf database detail" in namespace "sl2" should eventually show link loss between 9.0 and 11.0 percent
    And show command "show ospf database detail" in namespace "sl2" should not contain "% (Anomalous)"
    # The same bound on OSPF sets its bit too. This is also the positive
    # control for the check just above: an OSPF loss A bit renders as
    # "% (Anomalous)".
    When I apply command "set router ospf area 0.0.0.0 interface sl1-sl2 te-metric measurement loss anomaly-threshold 5" in namespace "sl1"
    Then show command "show ospf database detail" in namespace "sl2" should eventually contain "% (Anomalous)"
    # Recovery. The bucket the drop stops in is still lossy, the next is
    # clean, and the bit clears only a whole loss interval (30 s) after
    # the value first fell below the reuse bound: up to about 95 s in
    # all. The unit tests pin that wait; this checks the bit does clear
    # end to end.
    When I stop dropping STAMP probes in namespace "sl2"
    Then show command "show isis database detail" in namespace "sl2" should not contain "% (A)" within 120 seconds
    And show command "show ospf database detail" in namespace "sl2" should not contain "% (Anomalous)" within 60 seconds
    And show command "show stamp session" in namespace "sl1" should contain "loss: advertised 0." within 60 seconds
    When I apply command "delete router isis interface sl1-sl2 te-metric measurement loss anomaly-threshold" in namespace "sl1"
    And I apply command "delete router isis interface sl1-sl2 te-metric measurement loss reuse-threshold" in namespace "sl1"
    And I apply command "delete router ospf area 0.0.0.0 interface sl1-sl2 te-metric measurement loss anomaly-threshold" in namespace "sl1"
    Then show command "show stamp session" in namespace "sl1" should eventually not contain ", anomaly "

  Scenario: Probes that all vanish withdraw the loss at once
    Given the test topology exists
    # Design D8, judged on the latest bucket. sl1 goes back to the default
    # 120 s loss window for this, so a withdrawal that waited for the
    # whole window to fall silent would take two minutes or more. The
    # latest-bucket rule withdraws as soon as one whole 30 s bucket has
    # had no reply — within 60 s of the drop starting. The bucket the
    # drop began in still holds replies from before it; a value built
    # from it reads as near-total loss, which is why waiting for the
    # window is wrong.
    When I apply command "set router isis interface sl1-sl2 te-metric measurement loss interval 120" in namespace "sl1"
    And I apply command "set router ospf area 0.0.0.0 interface sl1-sl2 te-metric measurement loss interval 120" in namespace "sl1"
    # Precondition: a value is actually advertised under the 120 s
    # window before the drop. Without it the deadline below passes
    # vacuously — a session younger than 120 s has no full window, so it
    # reads "not advertised" before the drop has done anything. (That is
    # how an earlier version of this scenario passed against the
    # whole-window rule it exists to reject.) "…% (interval 120s" matches
    # only an advertised value; a withdrawn one reads "not advertised
    # (interval 120s".
    Then show command "show stamp session" in namespace "sl1" should contain "% (interval 120s" within 180 seconds
    When I drop all STAMP probes arriving in namespace "sl2"
    Then show command "show stamp session" in namespace "sl1" should contain "loss: not advertised (interval 120s" within 75 seconds
    And show command "show isis database detail" in namespace "sl2" should eventually show no link loss between 9.0 and 100.0 percent
    And show command "show ospf database detail" in namespace "sl2" should eventually show no link loss between 9.0 and 100.0 percent
    And show command "show isis neighbor" in namespace "sl2" should eventually contain "Up"
    # Back to the 30 s window so recovery fits the run, then restore the
    # probes: sl1 advertises a clean value again.
    When I apply command "set router isis interface sl1-sl2 te-metric measurement loss interval 30" in namespace "sl1"
    And I apply command "set router ospf area 0.0.0.0 interface sl1-sl2 te-metric measurement loss interval 30" in namespace "sl1"
    And I stop dropping STAMP probes in namespace "sl2"
    Then show command "show stamp session" in namespace "sl1" should contain "loss: advertised 0." within 150 seconds
    And show command "show isis database detail" in namespace "sl2" should eventually show no link loss between 1.1 and 100.0 percent

  Scenario: Against a stateful reflector, loss is split by direction
    Given the test topology exists
    # Design D3. Every 10th reply arriving at sl1 is dropped: 10 % loss
    # on sl1's return path alone. With the default stateless reflector
    # that is 10 % round-trip, and both IGPs advertise it.
    When I drop every 10th STAMP reply arriving in namespace "sl1"
    And I wait 30 seconds
    Then show command "show isis database detail" in namespace "sl2" should eventually show link loss between 9.0 and 11.0 percent
    And show command "show ospf database detail" in namespace "sl2" should eventually show link loss between 9.0 and 11.0 percent
    # sl2 reflects statefully, and IS-IS on sl1 declares it. IS-IS now
    # advertises forward loss — about none — while OSPF, which declared
    # nothing, keeps the round-trip 10 %.
    When I apply command "set router isis interface sl2-sl1 te-metric measurement reflector stateful" in namespace "sl2"
    And I apply command "set router isis interface sl1-sl2 te-metric measurement loss peer-reflector stateful" in namespace "sl1"
    Then show command "show stamp session" in namespace "sl2" should eventually contain "Reflector: stateful"
    And show command "show stamp session" in namespace "sl1" should contain "advertised 0.000000% forward" within 120 seconds
    And show command "show isis database detail" in namespace "sl2" should eventually show no link loss between 1.1 and 100.0 percent
    And show command "show ospf database detail" in namespace "sl2" should eventually show link loss between 9.0 and 11.0 percent
    # Now the loss moves to the forward path. This is what proves the
    # reflector stateful: against a stateless one, a forward loss also
    # reads as reverse, and IS-IS's forward value would stay at zero.
    When I stop dropping STAMP probes in namespace "sl1"
    And I drop every 10th STAMP probe arriving in namespace "sl2"
    And I wait 30 seconds
    Then show command "show isis database detail" in namespace "sl2" should eventually show link loss between 9.0 and 11.0 percent
    And show command "show stamp session" in namespace "sl1" should contain "direction over 30s: forward " within 5 seconds
    When I stop dropping STAMP probes in namespace "sl2"
    And I apply command "delete router isis interface sl2-sl1 te-metric measurement reflector" in namespace "sl2"
    And I apply command "delete router isis interface sl1-sl2 te-metric measurement loss peer-reflector" in namespace "sl1"
    Then show command "show stamp session" in namespace "sl2" should eventually contain "Reflector: stateless"

  Scenario: Turning loss off in one IGP leaves the other advertising it
    Given the test topology exists
    # Design D10: `loss enabled` belongs to each IGP, not to the shared
    # session. With IS-IS's loss off on both routers, no loss sub-TLV is
    # left in the IS-IS database, while OSPF on the same sessions keeps
    # advertising.
    When I apply command "set router isis interface sl1-sl2 te-metric measurement loss enabled false" in namespace "sl1"
    And I apply command "set router isis interface sl2-sl1 te-metric measurement loss enabled false" in namespace "sl2"
    Then show command "show stamp session" in namespace "sl1" should eventually contain "loss: disabled"
    And show command "show isis database detail" in namespace "sl2" should eventually not contain "Unidirectional Link Loss"
    And show command "show ospf database detail" in namespace "sl2" should eventually contain "Unidirectional Link Loss"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "sl1"
    And I stop zebra-rs in namespace "sl2"
    And I delete namespace "sl1"
    And I delete namespace "sl2"
    Then the test environment should be clean
