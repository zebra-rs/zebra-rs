# Well-Known Communities

BGP communities are 32-bit tags carried on routes (RFC 1997). Most
values are operator-defined and only mean something to the policies
that match on them, but a handful of **well-known** values from the
reserved `0xFFFF0000`–`0xFFFFFFFF` block have standardized,
router-enforced semantics. This chapter describes which of those
zebra-rs enforces automatically, and what the rest do.

Communities are stored as a **set**: duplicates collapse, and `show`
output and re-advertised UPDATEs render the values in canonical sorted
order regardless of the order they arrived in.

## Attaching communities

Communities are attached through policy `set community` (see the
[Policy — Set](ch-05-03-policy-set.md) chapter). Well-known values can
be written by name:

```yaml
community-set:
- name: comm-no-export
  members:
  - no-export
policy:
- name: set-no-export
  entry:
  - number: 10
    action: permit
    set:
      community:
        name: comm-no-export
```

Recognized names: `no-export`, `no-advertise`, `no-export-sub-confed`,
`local-AS`, `no-peer`, `graceful-shutdown`, `accept-own`, `blackhole`,
`llgr-stale`, `no-llgr`, and the `route-filter-*` reserved values.
Anything else is written as `ASN:NN` or a plain 32-bit number.

## Enforced: NO_EXPORT and NO_ADVERTISE (RFC 1997)

```
 ┌─────────┐   eBGP   ┌─────────┐   iBGP   ┌─────────┐
 │    A    │ ──────── │    B    │ ──────── │    C    │
 │ AS65001 │          │ AS65002 │          │ AS65002 │
 └─────────┘          └────┬────┘          └─────────┘
                           │ eBGP
                      ┌────┴────┐
                      │    D    │
                      │ AS65003 │
                      └─────────┘
```

- **`no-export` (0xFFFFFF01)** — the route must not leave the AS. When
  B holds a route carrying `no-export`, it still advertises it to its
  iBGP peer C, but suppresses it toward the eBGP peer D. If the route
  was already advertised before the community appeared, B withdraws
  it from the affected peers.
- **`no-advertise` (0xFFFFFF02)** — the route must not be advertised
  to *any* peer. B keeps the route for its own forwarding but sends it
  to neither C nor D.
- **`no-export-sub-confed` / `local-AS` (0xFFFFFF03)** — defined as
  "do not advertise outside the confederation member-AS". zebra-rs
  does not implement confederations, so this behaves exactly like
  `no-export` (FRR does the same without confederations).

Enforcement applies on every egress path — IPv4/IPv6 unicast,
VPNv4/VPNv6, labeled-unicast, and EVPN. SR Policy (SAFI 73) has its
own RFC 9830 handling of `no-advertise`.

### Ordering: your own egress policy does not self-suppress

The check runs **before** the per-neighbor outbound policy. A
community that your own `policy out` attaches toward a neighbor does
not suppress that very advertisement — only communities already on
the route (received from a peer, or set at origination/ingress)
suppress. In the topology above, A can attach `no-export` with an
outbound policy toward B: A still sends the route to B, and it is B
that honours the community on its own eBGP edges. This matches FRR's
evaluation order.

## Enforced: LLGR_STALE and NO_LLGR (RFC 9494)

These two drive Long-Lived Graceful Restart:

- **`llgr-stale` (0xFFFF0006)** — marks a route retained by an LLGR
  helper as *stale*. zebra-rs attaches it when stale-marking routes of
  a failed LLGR-negotiated session, and treats any route *received*
  with the community as least-preferred in best-path selection (the
  `S` code in `show` output). Stale routes are only re-advertised to
  peers that themselves sent the LLGR capability — a peer that never
  negotiated LLGR has no way to treat the route as stale, so it is
  suppressed instead (visible in the `LLGR-excluded` counter of
  `show bgp update-group`). The community is never stripped on
  re-advertisement.
- **`no-llgr` (0xFFFF0007)** — a peer marks a route it does not want
  retained long-lived. At stale-marking time such routes are removed
  and withdrawn per normal RFC 4271 operation instead of being
  retained.

Stale retention itself currently covers the VPNv4 and EVPN tables of
an LLGR-negotiated session.

## Recognized but policy-level

The remaining well-known values are parsed, displayed, and matchable
in policy, but carry no automatic behavior:

| Community | Notes |
|---|---|
| `graceful-shutdown` (RFC 8326) | Lower preference on receipt / attach on drain is an operator policy today; a dedicated knob may come later. |
| `blackhole` (RFC 7999) | Installing a discard route for tagged prefixes is operator policy. |
| `accept-own` (RFC 7611) | Route-reflector/VPN niche; not implemented. |
| `no-peer` (RFC 3765) | **Advisory by design** — a router cannot determine "bilateral peer vs transit" automatically, so it is intentionally not enforced (FRR does not enforce it either). |
