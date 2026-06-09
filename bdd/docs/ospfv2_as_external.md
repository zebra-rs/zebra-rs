# OSPFv2 AS-External (Type-5) LSA origination with E1 and E2 metric types

## Overview

As a network operator
I want zebra-rs to act as an OSPFv2 ASBR — originating Type-5 AS-External
LSAs from redistributed connected routes — so that routers in all areas
install the external prefix, and the metric type (E1 vs E2) is correctly
computed and varies by observer location for E1.
Same six-router three-area topology as ospfv2_multi_area:
Area 0: a (ABR), b (ASBR), c (ABR), d.
Area 0.0.0.1: a (ABR), e (internal).
Area 0.0.0.2: c (ABR), f (internal).
Router b is the ASBR in backbone area 0.  A connected network
(192.168.1.0/24) on a standalone dummy interface "cust0" is added to b
after zebra-rs starts.  It is NOT on any OSPF-enabled interface, so it
is a genuine external route — it enters the OSPF domain exclusively via
`redistribute connected` as a Type-5 AS-External LSA.  (An address on
an OSPF-enabled interface would instead be advertised as an intra-area
stub and summarized as a Type-3, which would win over the Type-5 and
mask the AS-External path being tested.)
E2 metric (type 2): the installed metric equals the LSA's external metric
(20) regardless of the observer's distance to the ASBR — the same [20]
appears on a (backbone, 1 hop), e (area 1, 2 hops), and f (area 2, 2 hops).
E1 metric (type 1): the installed metric equals SPF-cost-to-ASBR plus the
external metric.  b is connected to a and c at cost 10, so backbone routers
one hop away see [30] (10 + 20).  e reaches b via a (10) then via Type-4
from a (10), total ASBR cost 20, so it sees [40] (20 + 20).
Interface naming: on router X the interface toward router Y is "ethY".
Loopbacks: 10.0.0.X/32.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| E2 metric — same external metric from all observers | |
| E1 metric — external metric plus SPF cost to ASBR varies by location | |
