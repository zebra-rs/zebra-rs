# LOCAL_PREF received from an eBGP peer is silently ignored

## Overview

As a network operator
I want a LOCAL_PREF attribute arriving over an eBGP session to be
discarded on ingest (RFC 4271 §5.1.5, RFC 7606 §7.6)
So that an external neighbor — buggy or hostile — cannot steer my AS's
best-path selection, and the bogus value is never relayed to my iBGP
peers.

RFC 4271 §5.1.5: "A BGP speaker MUST NOT include this attribute in
UPDATE messages it sends to external peers ... If it is contained in an
UPDATE message that is received from an external peer, then this
attribute MUST be ignored by the receiving speaker." Because every real
router strips LOCAL_PREF on eBGP egress, only a scripted speaker can put
the DUT's ingress on the spot.

Three consequences of honoring the attribute are pinned, each in its own
scenario so the failure names the broken half:
- the Loc-RIB row carries the foreign LOCAL_PREF (visible in `show bgp`);
- best-path selection is steered: the eBGP path with LOCAL_PREF 500 beats
- the value is relayed AS-wide: z1 re-advertises the route to its iBGP

Silently ignored also means the session survives the UPDATE and the
routes themselves are accepted with their other attributes intact.

## Test Topology

```
  ┌─────────────────────────────────────────────────────────┐
  │                          br0                            │
  └───────┬────────────────────┬────────────────────┬───────┘
     ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
     │   h1    │          │   z1    │          │   z2    │
     │ scripted│          │  (DUT)  │          │ zebra-rs│
     │  eBGP   │─eBGP────▶│ AS65030 │◀────iBGP─│ AS65030 │
     │ AS65031 │          │192.168. │          │192.168. │
     │ .40.2/24│          │ 40.1/24 │          │ 40.3/24 │
     └─────────┘          └─────────┘          └─────────┘
```

## Notes

h1 runs tests/scripts/bgp_ebgp_local_pref_send.py: it announces
10.98.0.0/24 and 10.99.0.0/24 with next-hop 192.168.40.2, AS_PATH 65031
and LOCAL_PREF 500, then acts on trigger files, each consumed when it
fires: /tmp/bgp_ebgp_local_pref_ignore.announce and .withdraw.

z2 originates 10.99.0.0/24 (`network`), so z1 holds two candidates for
it: iBGP from z2 (LOCAL_PREF 100 by default, empty AS_PATH) and eBGP
from h1 (bogus LOCAL_PREF 500, AS_PATH 65031). 10.98.0.0/24 comes from
h1 only and is relayed to z2.

## Config Files

- z1.yaml: DUT — eBGP to h1 (passive), iBGP to z2.
- z2.yaml: iBGP peer of z1; originates 10.99.0.0/24.

## Test Scenarios

| Scenario | Result |
|----------|--------|
| Setup topology and establish sessions | |
| The UPDATE is accepted with its other attributes and the session stays up | |
| The eBGP-received LOCAL_PREF is not stored on the Loc-RIB row | |
| Best-path selection is not steered by the eBGP LOCAL_PREF | |
| The bogus LOCAL_PREF is not relayed to the iBGP peer | |
| Withdrawing the eBGP routes leaves only z2's origination | |
| Teardown topology | |
