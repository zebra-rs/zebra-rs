# BGP local-as presents a substitute AS to one neighbor (AS migration)

## Overview

As a network operator
I want `neighbor X local-as ASN [no-prepend] [replace-as] [dual-as]`
So a router migrated to a new global AS keeps its sessions with peers
that still expect the old AS, and each peer migrates on its own schedule.

## Test Topology

```
   ┌─────────┐  192.168.0.0/24  ┌─────────┐
   │   z1    │ i1────────────i1 │   z2    │
   │ AS65100 │                  │ AS65001 │
   │  .0.1   │   local-as       │  .0.2   │
   └─────────┘   64999 →        └─────────┘
```

## Notes

z1's global AS is 65100 but z2's `remote-as` names the pre-migration
AS 64999 — only z1's `local-as 64999` lets the session establish: the
OPEN carries 64999, outbound routes are prepended "64999 65100"
(`replace-as` hides the real AS → "64999"), and inbound routes from
z2 get 64999 prepended at ingress (`no-prepend` turns that off).
`dual-as` closes the migration: once z2 flips its remote-as to 65100,
one Bad Peer AS round trip makes z1's next OPEN present the global
AS. z2 is passive throughout so z1 always dials — the dual-as
retry exchange stays a single deterministic connection stream.

## Config Files

- z1-base.yaml:      z1 with bare `local-as 64999`, originates 10.0.0.1/32
- z1-replace.yaml:   z1 with `local-as 64999 replace-as true`
- z1-noprepend.yaml: z1 with `local-as 64999 no-prepend true`
- z1-dualas.yaml:    z1 with `local-as 64999 dual-as true`
- z2.yaml:           z2 expecting remote-as 64999 (passive), originates 10.0.0.2/32
- z2-globalas.yaml:  z2 migrated to remote-as 65100 (passive)

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology — the session establishes under the substitute AS | |
| Bare form prepends the substitute on both directions | |
| replace-as hides the real AS on egress | |
| no-prepend leaves inbound routes untouched | |
| dual-as re-establishes under the global AS after the peer migrates | |
| Teardown topology | |
