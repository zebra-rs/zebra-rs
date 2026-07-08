# BGP policy set ext-community and set large-community

## Overview

As a network operator
I want policy-list `set ext-community` and `set large-community`
actions to stamp the EXT_COMMUNITIES and LARGE_COMMUNITIES attributes
on routes, so that I can tag routes the same way `set community` tags
the standard COMMUNITIES attribute.

Both actions reference a named set (`ext-community-set` /
`large-community-set`); only the set's exact members contribute
concrete values (regex members are skipped). `replace` (default)
overwrites the attribute, `additive` merges, `delete` removes — the
same {replace|additive|delete} choice as `set community`.

The set is applied as z2's INBOUND policy so the modified attribute
lands in z2's own Loc-RIB and is directly observable via
`show bgp -j`, which now surfaces `community`, `ext_community`, and
`large_community` fields.

## Test Topology

```
  ┌─────────────────────────────────────────┐
  │                   br0                    │
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

- z1.yaml: AS 65001, advertises 10.0.0.1/32 + 10.0.0.2/32.
- z2-base.yaml: AS 65002, no input policy; routes carry no communities.
- z2-set-ext.yaml: `set ext-community RT-SET` (rt:65001:100).
- z2-set-large.yaml: `set large-community LC-SET` (65001:100:200).
- z2-set-both.yaml: one entry sets both rt:65002:300 and 65002:400:500.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish BGP session | |
| set ext-community stamps the EXT_COMMUNITIES attribute | |
| set large-community stamps the LARGE_COMMUNITIES attribute | |
| one entry sets both ext-community and large-community | |
| Teardown topology | |
