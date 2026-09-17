# Statically configured TE link metrics in all three IGPs

## Overview

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

This is the counterpart to stamp_te_metric and stamp_v6_te_metric,
which cover the measured path. Those can only assert that a delay
field is present, because the measured value varies run to run; here
the values are known, so the encodings are checked exactly — including
the RFC 8570 §4.4 loss unit of 0.000003 %, where 333 is 0.000999 %.

No Segment Routing is configured anywhere here, deliberately. TE
metrics ride the Extended-Link Opaque LSA (OSPFv2) and the
E-Router-LSA (OSPFv3), both of which used to be originated only when
SR was on — so an operator who configured link delay and no SR
advertised nothing, silently. SR now gates the Adj-SID and End.X
contributions rather than the LSA, and this feature is the gate on
that: if either LSA regains an SR precondition, every OSPF assertion
below fails.

Topology:

## Config Files


## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the dual-stack topology | |
| All three IGPs form adjacencies | |
| IS-IS advertises its configured values verbatim | |
| OSPFv2 advertises its own, different values | |
| OSPFv3 advertises its own values at the OSPFv3 code points | |
| Static values are never advertised as anomalous | |
| A pinned bound survives measurement being switched on | |
| Teardown topology | |
