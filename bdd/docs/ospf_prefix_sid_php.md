# The hop before a Prefix-SID's owner pops its label only without NP

## Overview

As a network operator
I want the router next to a Prefix-SID's owner to pop the label
(penultimate-hop popping) only when the owner's Prefix-SID leaves the
NP flag clear, and to keep the label when NP is set (RFC 8665 §5,
RFC 8666 §5) — for traffic it originates (FTN) and traffic it
forwards (ILM), in OSPFv2 and OSPFv3 alike.

zebra-rs sets NP on an index-form Prefix-SID and leaves it clear on an
absolute-label one. OSPFv2 used to pop next to every owner, NP or not;
OSPFv3 used to keep every label, NP or not.

## Test Topology

```
    r1 ---------------- r2 ---------------- r3
    absolute-label SID                      index SID
    v2 17001, v3 17021                      v2 index 3 = 16003
    (NP clear)                              v3 index 23 = 16023 (NP set)
```

## Notes

r2 is the penultimate hop toward both: it pops r1's labels and keeps
r3's.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Build the topology | |
| OSPFv2 keeps r3's label and pops r1's | |
| OSPFv3 keeps r3's label and pops r1's | |
| Teardown topology | |
