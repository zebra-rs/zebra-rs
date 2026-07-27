# A route reflector preserves EVPN SRv6 L2 service SIDs

## Overview

As an operator running EVPN through route reflectors — the normal
deployment, since a full iBGP mesh between PEs does not scale
I want a reflected Type-2 / Type-3 to reach the far PE with its SRv6 L2
Service TLV (RFC 9252) intact, so that EVPN-over-SRv6 works in a
reflected fabric and not only over a direct PE-to-PE session.

The Prefix-SID is an optional transitive attribute, so an RR is required
to pass it through untouched. Nothing tested that it survives
reflection: every other EVPN-over-SRv6 feature peers the PEs directly,
where the attribute never passes through a third speaker.

The topology is what makes the assertion airtight. The reflector runs no
VNI, no locator and no `encapsulation srv6`, so it can carve no SID of
its own; pe2 likewise has no locator. Any SID in pe2's EVPN RIB
therefore came from pe1 by reflection — and it must render as a "Remote
SID", never a "Local SID". The Originator-ID / Cluster-List that RFC
4456 requires the reflector to add is asserted alongside, so a route
that somehow arrived without being reflected would not pass either.

```
```

## Config Files

- pe1.yaml, rr.yaml, pe2.yaml — each PE peers ONLY with the reflector.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup the reflected EVPN fabric | |
| The reflector carries pe1's Type-3 IMET and its End.DT2M SID | |
| pe2 receives the reflected Type-3 with the SID intact | |
| A reflected Type-2 keeps its End.DT2U SID through the RR | |
| Withdrawing through the reflector clears the far PE | |
| Teardown topology | |
