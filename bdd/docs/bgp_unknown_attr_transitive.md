# BGP unrecognized path attribute handling (RFC 4271 §9)

## Overview

As a network operator
I want zebra-rs to follow RFC 4271 §9 for unrecognized path attributes
So an optional transitive unknown attribute survives and propagates with
the Partial bit set, while an optional non-transitive one is dropped.

## Test Topology

```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐  192.168.1.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │ i2────────────i1 │   z3    │
   │ AS65001 │                  │ AS65002 │                  │ AS65003 │
   │ .0.1    │                  │.0.2 .1.2│                  │ .1.3    │
   └─────────┘                  └─────────┘                  └─────────┘
```

## Notes

z1 originates 10.0.0.1/32. The debug knob `attach-unknown-attribute`
on z1's session toward z2 stamps a synthetic unrecognized path
attribute onto that route. Neither z2 nor z3 recognize the Type Code,
so they exercise the receiver-side RFC 4271 §9 rules:
  * Optional Transitive (flags 0xC0) → z2 accepts it, sets the Partial
    bit, retains it, and re-advertises to z3 (which also keeps it,
    Partial still set).
  * Optional non-Transitive (flags 0x80) → z2 silently drops it; it
    never reaches z3, and the 10.0.0.1/32 route itself is unaffected.

## Config Files

- z1-base.yaml:          z1 originates 10.0.0.1/32, no attach.
- z1-transitive.yaml:    z1 attaches type 250, flags 0xC0, value deadbeef.
- z1-nontransitive.yaml: z1 attaches type 251, flags 0x80, value 1234.
- z2.yaml / z3.yaml:     plain transit / tail speakers.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup line topology and establish all sessions | |
| Baseline - the route propagates with no unknown attributes | |
| Optional transitive unknown attribute is retained, Partial set, and propagated | |
| Optional non-transitive unknown attribute is dropped and not propagated | |
| Teardown topology | |
