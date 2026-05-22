# BGP Timer Configuration

BGP behaviour is shaped by a handful of timers that govern session
liveness, retry cadence, and how aggressively the speaker batches
outbound advertisements. This chapter documents the timers zebra-rs
exposes today, the defaults it ships with, and the operational
trade-offs behind tuning them.

Per-neighbor timers live under each neighbor; the global advertisement
interval lives under `router bgp timer`.

```
router bgp {
  timer {
    adv-interval {
      ibgp 5;
      ebgp 30;
    }
  }
}
```

Defaults are chosen to match RFC 4271 §10 and the Cisco IOS-XR
implementation where the semantics align, so configurations written
against IOS-XR carry across without surprise.

## Advertisement interval (MRAI)

The **MinRouteAdvertisementInterval** (MRAI) — RFC 4271 §9.2.1.1 — is
the minimum time a BGP speaker waits between successive advertisements
of routes carrying overlapping NLRI. Internally it acts as a
coalescing knob: when a route change arrives, zebra-rs starts a
debounce timer; further changes that land before the timer fires are
batched into the same MP_REACH UPDATE per attribute group. Without
this debounce, a flap or a burst of redistribute events would
translate into one UPDATE per change.

zebra-rs splits the MRAI by peer type so iBGP can run a faster cadence
than eBGP — typical in operator networks where iBGP sees more
frequent intra-AS route churn while eBGP cadence is shaped by
peering-policy concerns.

| YANG leaf | Default | Range | Units |
|---|---|---|---|
| `/router/bgp/timer/adv-interval/ibgp` | 5 | 0..65535 | seconds |
| `/router/bgp/timer/adv-interval/ebgp` | 30 | 0..65535 | seconds |

The defaults follow RFC 4271 §10: 5 s for internal sessions, 30 s for
external sessions.

**Scope.** The setting is global to the BGP instance. Every iBGP
update-group reads the `ibgp` value; every eBGP update-group reads the
`ebgp` value. Per-neighbor override is not supported in this revision
— the IETF `advertisement-interval` leaf under `neighbor … timers`
remains in the schema but is not yet wired into the advertise pipeline.

**Live application.** When either value changes via configuration,
zebra-rs re-snapshots the new cadence onto every existing peer and
update-group. Already-armed debounce timers keep running with their
captured value until they fire — there is no observable benefit to
cancelling them early, since the MRAI is a coalescing knob rather
than a session timer. The very next batch flush therefore uses the
new value.

**Tuning trade-offs.**

- Lowering MRAI shortens advertisement latency at the cost of more
  UPDATEs (potentially one per route change) and higher peer-side
  decode load.
- Raising MRAI lets more changes pack into a single MP_REACH UPDATE
  per attribute group, reducing message count at the cost of slower
  convergence.
- An MRAI of `0` disables the debounce entirely — every route change
  ships immediately. Useful in lab environments and when running
  against a peer that does its own coalescing; not recommended in
  production.
- The MRAI applies to advertisements, not withdrawals. Withdraw
  messages are not held by the timer.

**Worked example — converging a redistribute burst.**
Suppose a redistribute trigger injects 200 prefixes within 100 ms onto
a router with iBGP sessions to four route-reflector clients. With the
default 5-second iBGP MRAI:

1. The first NLRI lands in the update-group's pending-advert cache and
   arms a 5-second debounce timer.
2. The remaining 199 prefixes accumulate into the same cache during
   the debounce window, bucketed by attribute set.
3. On fire, the cache drains: each attribute bucket becomes one
   MP_REACH UPDATE containing all of its NLRIs, replicated once per
   non-source member of the update-group.

Net wire result: a small number of large UPDATEs instead of 200 tiny
ones, at the price of ≤ 5 seconds of advertisement latency.

## Per-neighbor session timers

The classic BGP session timers — keepalive, hold-time, connect-retry,
idle-hold, delay-open — are configured per neighbor under the IETF
`neighbor … timers` container and are documented in their respective
sections (their semantics match RFC 4271 unchanged).

These knobs control session liveness and reconnect cadence; they do
not interact with the MRAI debounce above. The advertisement pipeline
runs only against peers in the `Established` state, so MRAI tuning
affects message rate, not session establishment.
