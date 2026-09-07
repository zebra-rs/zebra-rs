# LOCAL_PREF received from an eBGP peer is silently ignored (IPv6)

## Overview

As a network operator
I want a LOCAL_PREF attribute arriving over an eBGP session to be
discarded on ingest for IPv6 unicast too (RFC 4271 §5.1.5, RFC 7606 §7.6)
So that an external neighbor cannot steer my AS's IPv6 best-path
selection, and the bogus value is never relayed to my iBGP peers.

The IPv6 twin of bgp_ebgp_local_pref_ignore. IPv6 unicast has its own
ingest path in zebra-rs (route_ipv6_update, MP_REACH_NLRI AFI=2/SAFI=1,
RFC 2545), so the discard has to be pinned per family — a fix on the
IPv4 path alone would leave this one open. The session itself runs over
IPv6 transport.

Three consequences of honoring the attribute are pinned, each in its own
scenario so the failure names the broken half:
- the Loc-RIB row carries the foreign LOCAL_PREF (visible in
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
     │ AS65031 │          │2001:db8:│          │2001:db8:│
     │ 40::2/64│          │ 40::1/64│          │ 40::3/64│
     └─────────┘          └─────────┘          └─────────┘
```

## Notes

h1 runs tests/scripts/bgp_ebgp_local_pref_send.py: it announces
2001:db8:98::/64 and 2001:db8:99::/64 in MP_REACH_NLRI with next-hop
2001:db8:40::2, AS_PATH 65031 and LOCAL_PREF 500, then acts on trigger
files, each consumed when it fires:
/tmp/bgp_ebgp_local_pref_ignore_v6.announce and .withdraw.

z2 originates 2001:db8:99::/64 (`network`), so z1 holds two candidates
for it: iBGP from z2 (LOCAL_PREF 100 by default, empty AS_PATH) and eBGP
from h1 (bogus LOCAL_PREF 500, AS_PATH 65031). 2001:db8:98::/64 comes
from h1 only and is relayed to z2.

## Config Files

- z1.yaml: DUT — eBGP to h1 (passive), iBGP to z2, both over IPv6.
- z2.yaml: iBGP peer of z1; originates 2001:db8:99::/64.

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
