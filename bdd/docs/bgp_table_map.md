# BGP table-map gates and rewrites RIB installs without touching the Loc-RIB

## Overview

As a network operator
I want `router bgp afi-safi ipv4 table-map <policy>` to filter and
rewrite BGP best paths at the point they are installed into the
kernel RIB, while the BGP table itself (and what peers are
advertised) stays complete — FRR's table-map semantics.
The exercise: z1 advertises three prefixes. z2 binds table-map TMAP:
entry 10 denies 1.1.1.1/32, entry 20 permits 2.2.2.2/32 with
`set med 50` (MED lands in the kernel route metric), entry 30
permits the rest. All three prefixes must stay visible in z2's BGP
table throughout; only the kernel routes move. Live policy edits
must resync the FIB without a session clear, a rebind to a
nonexistent policy must deny every install (FRR parity), and
deleting the table-map must restore unfiltered installs.

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                   │
  └─────────────┬───────────────┬───────────┘
                │               │
           ┌────┴────┐     ┌────┴────┐
           │   z1    │     │   z2    │
           │ AS65001 │     │ AS65002 │
           │192.168. │     │192.168. │
           │  0.1/24 │     │  0.2/24 │
           └─────────┘     └─────────┘
```

## Config Files

- z1.yaml: AS 65001, advertises 1.1.1.1/32 + 2.2.2.2/32 + 3.3.3.3/32.
- z2.yaml: prefix-set DENY = { 1.1.1.1/32 }, MED = { 2.2.2.2/32 };
- z2-deny-more.yaml: DENY = { 1.1.1.1/32, 3.3.3.3/32 } (added).

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and verify install-time filter and MED rewrite | |
| Editing the referenced policy resyncs the FIB without a session reset | |
| Rebinding to a nonexistent policy denies every install | |
| Deleting the table-map restores unfiltered installs | |
| Teardown topology | |
