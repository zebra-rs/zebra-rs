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

A triggered failover logs the reset:

```
bgp: fast-external-failover: interface down — resetting eBGP peer peer=10.0.3.2 ifindex=3
```

and the neighbor drops out of `Established` in `show bgp summary`
immediately after the link event, rather than at hold-time expiry.
