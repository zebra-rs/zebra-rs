# Fast External Failover

When the interface carrying a **directly connected eBGP** session goes
operationally down, waiting for the hold timer (commonly 90–180 s) to
notice is pointless — the link event already proves the session is
dead. **Fast external failover** resets such sessions immediately on
the link-down event, so routes via the failed peer are withdrawn in
milliseconds instead of minutes.

It is **enabled by default**, matching IOS-XR (`bgp
fast-external-fallover`, XR spelling) and FRR
(`bgp fast-external-failover`). You only ever configure it to turn it
*off*.

## What it does

On a link-down (or link-removal) event for an interface, zebra-rs
immediately hard-resets every session that

- is **eBGP** — iBGP is never touched (it typically survives on an
  alternate IGP path), and
- is **single-hop** — the default TTL-1 case or `ttl-security` (GTSM,
  directly connected by definition); a neighbor configured with
  [`ebgp-multihop`](ch-02-11-bgp-ttl-security.md) is intentionally
  reachable through other paths and is left to hold-timer/NHT, and
- **rides the downed interface** — unnumbered interface-neighbors match
  by their interface, numbered neighbors by the connected subnet their
  address lives on.

The reset is the same teardown as
[`clear bgp <peer>`](ch-02-25-bgp-clear.md): routes learned from the
peer are withdrawn, the TCP connection is closed (no NOTIFICATION is
sent — the link is down, nothing would be delivered), and the session
re-dials automatically, so it comes back on its own once the link
returns. When the interface comes back up, zebra-rs additionally
re-kicks peers parked on it, so recovery does not wait out the
connect-retry backoff either.

What counts as *down* is the operational state: admin-down or loss of
carrier (`LOWER_UP` cleared). On a point-to-point link (a veth pair, a
direct fiber) cutting either end drops carrier on **both** routers, so
both sides fast-reset — this is exactly what the BDD feature
(`bgp_fast_external_failover`) validates. Across a switch, only the
router whose own port failed loses carrier; the far side still sees
link-up and keeps waiting on the hold timer, so pair the feature with
BFD when the path between the peers is switched.

With the feature disabled, a link cut is only detected when the hold
timer expires — or by [BFD](ch-02-08-bgp-bfd.md), which detects
*forwarding* failures the link state never reports and works for
multihop/iBGP too. The two are complementary: fast external failover is
free and instant for the link-flap case; BFD covers everything else.

## Configuration

The knob is a global boolean, on by default. To disable (the IOS-XR
`bgp fast-external-fallover disable` equivalent):

```yaml
router:
  bgp:
    global:
      as: 65001
      router-id: 10.255.0.1
      fast-external-failover: false
```

CLI form:

```
set router bgp global fast-external-failover false
```

Deleting the line restores the default (enabled). Flipping the knob
never bounces established sessions — it only changes how the *next*
link-down is handled.

| Path | Default | Meaning |
|------|---------|---------|
| `/router/bgp/global/fast-external-failover` | `true` | Reset directly connected eBGP sessions immediately on interface down. |

## When to disable it

Rarely. The classic reason is a flapping last-mile link where the
carrier drops for hundreds of milliseconds at a time: each flap resets
the session and forces a full route exchange, which can be worse than
riding through the flap on the hold timer. Interface-level dampening
(holding the link down in hardware) is usually the better fix; failing
that, `fast-external-failover false` keeps the session pinned through
short link drops.

## Verification

A triggered failover logs the reset at `warn` level:

```
WARN zebra-rs/src/bgp/inst.rs: bgp: fast-external-failover: interface down — resetting eBGP peer peer=10.107.0.2 ifindex=207
```

and the neighbor drops out of `Established` in `show bgp summary`
immediately after the link event, rather than at hold-time expiry.
The cause is recorded on the neighbor and survives re-establishment:

```
show bgp neighbor 10.107.0.2
  ...
  Last reset 00:00:07, due to Interface down
```

(Other reset causes — `BFD down`, `Hold timer expired`, `NOTIFICATION
received`, `Admin. reset` for `clear bgp … hard`, `Config change` for a
knob bounce — are reported on the same line.)
When the link returns, the session re-establishes right away — link-up
re-kicks peers parked on that interface instead of leaving them to the
connect-retry backoff.

The full behavior — immediate reset on link-down at both ends of a
point-to-point link, prompt recovery on link-up, and the session
riding through the same cut when the knob is off — is exercised
end-to-end by the BDD feature `bdd/tests/features/bgp_fast_external_failover.feature`.
