# BGP EVPN VPWS multihoming — ESI and DF-elected P/B (RFC 8214 §5)

## Overview

As a network operator
I want a VPWS service whose attachment circuit sits on a multihomed
Ethernet Segment to advertise its Type-1 under that segment's ESI, and to
elect its primary/backup role per <ESI, VPWS service instance> across the
PEs advertising the segment's Type-4, so the remote PE learns which of the
two attached PEs to use — and learns it again, without any config change,
when one of them leaves the segment.
Control-plane only: no cradle dataplane is attached, so this asserts the
Type-1 ESI, the Layer-2 Attributes P/B bits on the wire, and the role each
PE reports. Which SID the remote *binds* from a multihomed pair is remote
selection, a separate phase — z3 here still binds a single end.
Test Topology — three iBGP (AS 65001) EVPN speakers on a shared transport
bridge br0. z1 and z2 are dual-homed to one CE over Ethernet Segment es1
and both advertise VPWS service instance 101; z3 is the single-homed
remote end of the E-Line:
```
┌───────────────────────────────────────────────┐
│                      br0                      │
└────┬──────────────────┬──────────────────┬────┘
```
Instance 101 carves to ordinal 101 % 2 = 1 of the ascending VTEP list
[.0.1, .0.2], so z2 is the DF (primary) and z1 its backup — the lower
address deliberately is *not* the DF, which is what proves the carving
keys on the service instance id rather than just picking the lowest PE.

## Notes

Instance 101 carves to ordinal 101 % 2 = 1 of the ascending VTEP list
[.0.1, .0.2], so z2 is the DF (primary) and z1 its backup — the lower
address deliberately is *not* the DF, which is what proves the carving
keys on the service instance id rather than just picking the lowest PE.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology, two PEs on one Ethernet Segment plus a remote PE | |
| Both attached PEs originate the Type-1 under the segment's ESI | |
| Single-active carving elects one primary and one backup | |
| All-active makes every attached PE primary | |
| A PE leaving the segment re-elects the survivor with no config change on it | |
| An AC claimed by two segments is reported, not guessed; the leaf resolves it | |
| Preference-based DF election overrides the carving ordinal | |
| The remote PE binds the primary of a multihomed pair | |
| Losing the primary fails the service over to the backup | |
| Teardown topology | |
