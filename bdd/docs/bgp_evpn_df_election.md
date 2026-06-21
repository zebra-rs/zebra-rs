# BGP EVPN BUM segmentation — inter-AS DF election (RFC 9572 Section 5.3.1)

## Overview

As a network operator
I want the ASBRs that border a downstream AS to attach a DF Election Extended
Community (RFC 8584, AC-DF cleared) to their re-originated Per-Region I-PMSI
(Type-9) routes and elect a single Designated Forwarder, so a downstream AS
containing legacy PEs receives no duplicated BUM traffic.
Test Topology — region A (AS 65001) is bordered by TWO ASBRs, z2 (.0.2) and
z4 (.0.4), both re-originating region A's Type-9 toward the downstream AS
65002 (z3). z1 is a plain (legacy, non-segmentation) PE in region A.
```
┌──────────────────────────────────────────────────────────────────┐
│                               br0                                 │
└───────┬───────────────┬───────────────┬───────────────┬──────────┘
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish the EVPN sessions | |
| Both ASBRs attach a DF Election EC to their Per-Region I-PMSI | |
| The downstream AS elects the lowest-address ASBR as DF | |
| An ASBR flags the legacy (non-segmentation) PE in its region | |
| Teardown topology | |
