# enforce-first-as judges the AS_PATH the neighbor sent, not our local-as prepend (IPv6)

## Overview

As a network operator
I want `enforce-first-as` and `local-as` to work together on one neighbor
So an AS migration does not silently cost me every route from the
neighbors I have not migrated yet.

With a bare `local-as` (no `no-prepend`) zebra-rs prepends the
substitute AS to every route it receives from that neighbor, so the
rest of the network still sees the path through the old AS. The
first-AS check must look at the path as the neighbor sent it — FRR runs
it before the prepend. zebra-rs ran it after, saw the substitute AS
left-most, and dropped every route from the neighbor with nothing
logged. RFC 7606 §7.2 also says a route that fails the check "SHOULD"
be handled as treat-as-withdraw: the failing UPDATE replaces the
neighbor's earlier path for the prefix, so that path must go too.

## Test Topology

```
  ┌─────────────────────────────────────────────────────────┐
  │                  br0 2001:db8:47::/64                   │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   z2    │          │   z1    │          │   h3    │
     │ AS65001 │─eBGP────▶│  (DUT)  │◀────eBGP─│scripted │
     │  ::2    │ local-as │ AS65100 │          │ AS65003 │
     │         │  64999   │  ::1    │          │  ::3    │
     └─────────┘          └─────────┘          └─────────┘
```

## Notes

z1 runs `enforce-first-as` toward both neighbors. Toward z2, which
still expects z1's pre-migration AS, it also runs bare `local-as 64999`.
z2 originates 2001:db8:47:2::/64 with a correct first AS.

h3 runs tests/scripts/bgp_attr_inject_send.py. At session-up it
announces 2001:db8:47:3::/64 with AS_PATH "65003". On the trigger file
/tmp/bgp_enforce_first_as_local_as_v6.go it sends, in one write,
2001:db8:47:3::/64 again with AS_PATH "65099 65003" (a foreign first AS,
replacing the valid path) and the control prefix 2001:db8:47:4::/64 with
"65003". A zebra-rs neighbor cannot produce that UPDATE on its own: a
live policy change there withdraws the prefix before re-announcing it,
which hides whether z1 kept the superseded path.

## Config Files

- z1.yaml: DUT — enforce-first-as toward z2 (with local-as 64999) and
  h3 (passive); IPv6 unicast over IPv6 sessions.
- z2.yaml: the not-yet-migrated neighbor; originates 2001:db8:47:2::/64.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish sessions | |
| The neighbor without local-as passes the check with a correct first AS | |
| The local-as ingress prepend does not trip enforce-first-as | |
| A route that fails the check withdraws the neighbor's earlier path | |
| Teardown topology | |
