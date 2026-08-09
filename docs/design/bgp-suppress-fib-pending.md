# `bgp suppress-fib-pending`

Status: design proposal
Motivation: SONiC port — closes Phase 2, and the last gap that degrades
silently on every device

## Why

SONiC's default bgpd template emits `bgp suppress-fib-pending` on **every**
device, and runs zebra with `--asic-offload=notify_on_offload`. The two
together mean: do not tell a peer about a prefix until the ASIC has
actually programmed it.

Without the gate, the window between "BGP chose a path" and "syncd
programmed it" is a window in which we have advertised reachability we
cannot yet deliver. Traffic arrives and is dropped. On a leaf with a full
table and a churny upstream that window is not theoretical.

zebra-rs currently advertises immediately. The porting template therefore
*drops* the statement rather than refusing it — refusing would mean no
SONiC deployment starts at all — which makes this the one gap that is
silently degraded on every device rather than loudly refused on some.

## What already exists

The feedback loop is built and only the last hop is missing:

* `fpmsyncd` sends an `RTM_NEWROUTE` back over the same TCP socket with
  `RTM_F_OFFLOAD` set once APPL_STATE_DB confirms programming.
* The FPM client parses it and raises `FibMessage::RouteOffload`.
* `Rib::route_offload` (`rib/inst.rs`) maps the ack's VRF *ifindex* back
  to a table, finds the prefix, and calls `mark_selected_offloaded`,
  which sets `RibEntry::offloaded` on the selected entry only — the one
  that was actually installed.

And then it stops. Nothing tells BGP. `offloaded` is written and never
read.

## Semantics

Matching FRR, which is what SONiC's templates were written against:

1. The gate applies to a prefix **whose best path BGP itself installs**.
   A path we do not install has nothing to wait for.
2. On selecting a new best path, install to the FIB as today, but do
   **not** advertise. Record the prefix as FIB-pending.
3. On the offload ack, advertise.
4. A *withdraw* is never suppressed. Withdrawing is how we stop
   attracting traffic; delaying it can only prolong a blackhole. This
   asymmetry is the point of the feature, and getting it backwards would
   invert the whole thing.
5. A prefix already advertised, whose best path changes to another path
   that is also pending, keeps its current advertisement until the new
   one is acked. Implicit withdraw is the alternative, and it would
   convert a hardware-programming delay into a routing withdrawal
   visible to the whole fabric.
6. Disabling the knob at runtime releases everything currently pending
   immediately.

### The timeout, which is not optional

If an ack is lost — fpmsyncd restarts, orchagent rejects the route,
APPL_STATE_DB never settles — a suppressed prefix would never be
advertised. Silent, permanent, and invisible in `show bgp` unless
something says so.

So a pending prefix must have a bounded life: on expiry, advertise
anyway and count it. Advertising after a timeout is the safer failure —
the pre-feature behaviour — whereas never advertising is a black hole
that looks like a routing bug.

The counter matters as much as the timer: a device timing out
continuously is one whose FIB is not keeping up, and that should be
visible rather than inferred.

## Data model

On the BGP instance:

```rust
/// `router bgp suppress-fib-pending`.
pub suppress_fib_pending: bool,
/// Prefixes installed but not yet acked by the forwarding plane, with
/// the deadline after which they are advertised regardless.
pub fib_pending: BTreeMap<IpNet, Instant>,
```

A `BTreeMap` rather than a set because the deadline has to be somewhere,
and because the sweep wants them in a stable order.

Note the pending set holds prefixes, not paths. The ack carries no path
identity — `RouteOffload` has a prefix and a VRF ifindex and nothing else
— so a per-path key could not be matched back anyway.

## The notification path

`RibRx` is the existing RIB→protocol channel; add a variant:

```rust
/// The forwarding plane's verdict on a prefix this speaker installed.
/// `success = false` is a programming failure, not a timeout.
RouteOffload { prefix: IpNet, success: bool },
```

emitted from `Rib::route_offload` alongside the existing
`mark_selected_offloaded`, and delivered to subscribers that asked for
it. BGP already holds a `RibRx` subscription, so this is a new arm in an
existing loop rather than new plumbing.

Keeping `mark_selected_offloaded` is deliberate: the RIB's own copy of
the flag is what `show ip route` should eventually render, and it is the
thing to consult when a subscriber joins late.

## The gate

Three touch points, all narrow:

**1. Suppress the advertise.** `route_advertise_to_peers` (`bgp/route.rs`)
is the single per-prefix entry point every advertise path funnels
through — the serial reduce, the parallel batch, the peer-egress-task fan
and the update-group fan all reach it or its `_v6` twin. Gate there, so
one check covers every path:

```rust
if bgp.suppress_fib_pending
    && !selected.is_empty()                  // never suppress a withdraw
    && bgp.fib_pending.contains_key(&prefix.into())
{
    return;                                  // advertise on the ack
}
```

**2. Record on install.** Where the best path is handed to the RIB
(`fib_install_v4` / `_v6`), insert the prefix into `fib_pending` with a
deadline — but only when the knob is on, so the map stays empty and the
lookup above stays a no-op on a device that does not use the feature.

**3. Release on ack.** On `RibRx::RouteOffload`, remove the prefix and
call `route_advertise_to_peers` with the current selection. This is why
the entry point matters: the release path is the same function as the
normal path, so a released prefix cannot take a different code path from
one that was never suppressed.

A periodic sweep (the instance already has a timer tick) advertises and
counts anything past its deadline.

## Interaction with what is already there

**Multipath.** The pending key is the prefix, and the ack describes the
selected FIB entry — which for an ECMP set is the whole set. So a
multipath prefix releases once, when its entry is acked, not once per
leg.

**Graceful restart.** During our own restart the FIB is being
re-programmed wholesale, so every prefix is briefly pending. This is
exactly the interaction `select-defer-time` exists to manage in FRR, and
zebra-rs does not implement that deferral yet. Worth stating plainly:
until it does, enabling suppression makes a restart advertise later, not
sooner. Both belong to Phase 6 and should be tested together.

**VRF / VPN.** `route_offload` already resolves the VRF ifindex to a
table, so per-VRF acks land correctly. The pending map should be keyed by
`(table, prefix)` if this extends past the global instance — noted here
rather than built, since the SONiC port needs the default VRF first.

## Configuration

```yang
leaf suppress-fib-pending {
  ext:help "Advertise a prefix only after the FIB confirms it";
  type boolean;
  description
    "Hold a prefix out of the Adj-RIB-Out until the forwarding plane
     acknowledges programming it. Withdrawals are never suppressed.

     Requires a forwarding plane that acknowledges installs — the FPM
     tee against fpmsyncd does. With no acknowledger every prefix would
     rely on the timeout, so the knob would add latency and nothing
     else.";
}
```

at `/router/bgp/suppress-fib-pending`, beside the other instance-level
knobs.

Turning it **off** must flush `fib_pending` and advertise everything in
it, or those prefixes stay suppressed forever by a feature that is no
longer enabled.

## Show

`show bgp summary` should carry a pending count, and `show bgp <prefix>`
should say "FIB pending" for a suppressed path. Without that, the
difference between "not advertised because suppressed" and "not
advertised because policy denied it" is invisible, and they are debugged
completely differently.

The timeout counter belongs next to it.

## Tests

Unit:

* knob off → advertise is immediate (the existing behaviour, unchanged)
* knob on, no ack → not advertised
* knob on, ack arrives → advertised, pending set empties
* withdraw is never suppressed, including while the prefix is pending
* a best-path change while pending keeps the previous advertisement
  rather than withdrawing it
* ack with `success = false` → not advertised, and counted separately
  from a timeout
* deadline passes → advertised, counter incremented
* disabling the knob flushes and advertises everything pending

Integration (BDD), which is where this feature actually lives: two
speakers and a fake acknowledger; assert the peer sees the prefix only
after the ack, and that a lost ack surfaces as a timeout rather than a
prefix that never appears.

The `fpm-tap` rig already replays both ack modes — optimistic echo and
orchagent-driven — so the integration side has its acknowledger.

## Risks

**Withdraw suppression.** If the "never suppress a withdraw" condition is
wrong, the feature converts a programming delay into a prolonged
blackhole — the exact harm it exists to prevent. It is one line and it
deserves its own test.

**A stuck pending set is invisible.** Everything about this feature is
"traffic is not attracted yet", which looks like nothing at all from the
outside. The timeout, the counter and the `show` output are not polish;
they are what makes the failure debuggable.

**Hot-path cost.** The gate sits on the per-prefix advertise path. Keep
it a `BTreeMap` lookup guarded by the `bool`, so a device with the
feature off pays one branch.

## Scope

Not included:

* `select-defer-time` / restarting-speaker deferral — Phase 6, and
  tracked in `bgp-sonic-gaps.md`.
* Per-VRF pending keys — the global instance first.
* Suppressing on anything other than an install ack (e.g. BFD state).
