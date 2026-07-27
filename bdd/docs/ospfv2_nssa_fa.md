# NSSA Type-7 forwarding address is originated, translated, and resolved

## Overview

As a network operator
I want NSSA ASBRs to originate P-bit Type-7 LSAs with a non-zero
forwarding address (RFC 3101 §2.3), the ABR to preserve it when
translating to Type-5 (or zero it under `nssa-suppress-fa`), and
backbone receivers to resolve the external route via the FA's
intra/inter-area path (RFC 2328 §16.4 step 3) — previously such
LSAs were skipped entirely.

## Test Topology

```
     backbone            NSSA area 0.0.0.1
    b -- 10.0.12.0/30 -- a (ABR/translator) -- 10.0.13.0/30 -- c (ASBR)
                                          dummy on c: 10.9.9.0/24
    Type-7 from c carries FA 10.0.13.2 (c's NSSA interface); b's
    route to the external exists ONLY if it can resolve that FA via
    its inter-area route to 10.0.13.0/30.
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| FA-carrying external resolves on the backbone end to end | |
| nssa-suppress-fa zeroes the FA and routing still works via the ABR | |
| Teardown topology | |
