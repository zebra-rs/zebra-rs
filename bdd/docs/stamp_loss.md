# Measured link loss advertised by IS-IS and OSPF

## Overview

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

## Config Files


## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the measured topology | |
| Loss is advertised by default on a clean link | |
| A 10 percent probe loss is advertised by both IGPs | |
| Probes that all vanish withdraw the loss at once | |
| Turning loss off in one IGP leaves the other advertising it | |
| Teardown topology | |
