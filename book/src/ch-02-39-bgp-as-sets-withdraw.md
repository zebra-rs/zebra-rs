# AS_SET / AS_CONFED_SET Withdrawal (RFC 9774)

[RFC 9774](https://www.rfc-editor.org/rfc/rfc9774.html) deprecates
`AS_SET` and `AS_CONFED_SET` path-segment types in BGP. Unless a
network operator explicitly opts out during a transition period, a BGP
speaker must:

- **not originate** UPDATEs whose `AS_PATH` (or `AS4_PATH`) contains
  those segment types, and
- **treat-as-withdraw** (RFC 7606) any received UPDATE that carries
  them.

zebra-rs enforces this by default. The global boolean
`as-sets-withdraw` controls the behavior; it is **on by default**
(`true`). Set it to `false` only when you deliberately need legacy
`AS_SET` / `AS_CONFED_SET` handling — for example while migrating away
from an old aggregator.

FRR names the same feature `bgp reject-as-sets` (enabled by default
since FRR 10.5). The mapping is:

| zebra-rs | FRR |
|----------|-----|
| default (`as-sets-withdraw true`, or unset) | `bgp reject-as-sets` |
| `as-sets-withdraw false` | `no bgp reject-as-sets` |

## What it does

### Ingress

When `as-sets-withdraw` is enabled, an inbound UPDATE whose decoded
`AS_PATH` contains an `AS_SET` (`{…}`) or `AS_CONFED_SET` (`[…]`)
segment is handled like a malformed attribute under RFC 7606: the
reachable NLRI in that UPDATE are **treat-as-withdraw** — any copy of
those prefixes previously learned from this peer is removed, nothing
new is installed, explicit withdrawals in the same UPDATE are still
honoured, and the session stays up.

This is independent of per-neighbor knobs such as
[`enforce-first-as`](ch-02-15-bgp-enforce-first-as.md), which also
rejects routes whose path starts with an `AS_SET` but does so by
dropping the update before Adj-RIB-In processing rather than via the
RFC 7606 withdraw path.

### Egress

When enabled, a route whose post-egress `AS_PATH` would still contain
`AS_SET` or `AS_CONFED_SET` is **not advertised** to any peer (v4/v6
unicast, labeled unicast, VPN, EVPN, MUP, Flowspec). Locally
originated paths and normal eBGP prepends use `AS_SEQUENCE` only, so
this gate mainly blocks re-advertisement of legacy paths still present
in the Loc-RIB.

## Configuration

The knob is a global boolean under `router bgp`, on by default. To opt
out during a transition:

```yaml
router:
  bgp:
    global:
      as: 65001
      router-id: 10.255.0.1
    as-sets-withdraw: false
```

CLI form:

```
set router bgp as-sets-withdraw false
```

Deleting the line restores the default (enabled):

```
delete router bgp as-sets-withdraw
```

Flipping the knob does not reset established sessions; it applies to
the next received UPDATE and the next advertisement decision.

| Path | Default | Meaning |
|------|---------|---------|
| `/router/bgp/as-sets-withdraw` | `true` | RFC 9774 enforcement: withdraw on receive, do not advertise on send. |

## When to disable it

Rarely, and only temporarily. `AS_SET` and `AS_CONFED_SET` are
effectively absent on the public Internet; RFC 9774 standardizes the
deprecation because they complicate origin validation (RPKI-ROV,
BGPsec) and aggregation semantics.

Disable `as-sets-withdraw` only when you must interoperate with a
legacy speaker that still originates or expects `AS_SET` paths during
a controlled migration. Plan to re-enable the default once the
transition completes.

## Related reading

- [Enforce First AS](ch-02-15-bgp-enforce-first-as.md) — another
  inbound AS_PATH guard, scoped per neighbor and eBGP-only.
- Appendix B — [RFC 9774](appendix-b-supported-rfcs.md) and RFC
  7606 treat-as-withdraw handling.
