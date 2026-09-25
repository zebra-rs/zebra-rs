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
