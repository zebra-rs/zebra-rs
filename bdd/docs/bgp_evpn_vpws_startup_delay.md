# BGP EVPN startup-delay — hold a booting PE out of the DF election

## Overview

As a network operator
I want a PE that has just joined an Ethernet Segment to stay out of that
segment's Designated-Forwarder election for a configured number of
seconds, so it does not elect itself DF against a candidate set BGP has
not populated yet and start duplicating traffic the incumbent DF is
already forwarding toward the CE.

The hold works by withholding the segment's ES routes — the Type-4 and the
per-ES A-D — not by deferring only the local election. Deferring locally
would deadlock: the other PEs would still see our Type-4, still run the
same deterministic election over the same candidate set, and could hand
the DF role to a PE that is refusing to forward. Withholding the routes
keeps the holding PE out of their candidate sets entirely, so the
incumbent simply keeps forwarding. On the holding PE's own VPWS services
the hold forces the RFC 8214 §5 role to non-designated, so the remote PE
does not use it either.

Control-plane only: no cradle dataplane is attached, so this asserts the
routes on the wire, the Layer-2 Attributes P/B bits, and the state each PE
reports.

Test Topology — three iBGP (AS 65001) EVPN speakers on a shared transport
bridge br0. z1 and z2 are dual-homed to one CE over Ethernet Segment es1
and both advertise VPWS service instance 101; z3 is the single-homed
remote end of the E-Line. Only z1 carries a startup-delay:
```
┌───────────────────────────────────────────────┐
│                      br0                      │
└────┬──────────────────┬──────────────────┬────┘
```
With z1 holding, es1 has one candidate — z2 — and instance 101 carves to
ordinal 101 % 1 = 0, so z2 forwards alone. When the hold elapses the list
becomes [.0.1, .0.2] and instance 101 carves to ordinal 101 % 2 = 1: z2
keeps the DF role and z1 becomes its backup. The DF deliberately does not
move when z1 joins, so a role that flips to `backup` can only have come
from z1 rejoining the election.

## Notes

With z1 holding, es1 has one candidate — z2 — and instance 101 carves to
ordinal 101 % 1 = 0, so z2 forwards alone. When the hold elapses the list
becomes [.0.1, .0.2] and instance 101 carves to ordinal 101 % 2 = 1: z2
keeps the DF role and z1 becomes its backup. The DF deliberately does not
move when z1 joins, so a role that flips to `backup` can only have come
from z1 rejoining the election.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology, one holding PE and one incumbent on a shared segment | |
| The holding PE withholds its ES routes and stands its service down | |
| The incumbent keeps forwarding for the whole hold | |
| The hold elapses and the PE joins the election | |
| Re-configuring the delay re-arms the hold; clearing it ends the hold at once | |
| Teardown topology | |
