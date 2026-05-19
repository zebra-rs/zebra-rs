# IS-IS Timer Configuration

IS-IS behaviour is governed by a set of timers that control adjacency
liveness, database synchronization, self-LSP origination rhythm, and
convergence speed. This chapter documents each timer zebra-rs exposes,
its default, the semantics it carries on the wire or inside the local
state machine, and the operational considerations behind tuning it.

All timer configuration lives under the IS-IS instance:

```
router isis
  timers
    ...
  spf-interval
    ...
  interface <name>
    hello
      ...
    csnp-interval ...
    psnp-interval ...
```

Defaults are chosen to match Cisco IOS-XR where the semantics align,
so configurations written against IOS-XR's `router isis` model carry
across without surprise.

## Adjacency timers — hello-interval and hello-multiplier

Every active IS-IS interface periodically emits Intermediate-System
Hello (IIH) PDUs to discover and maintain neighbours. Each hello
carries a `holdingTime` field telling the receiver how long to keep
the adjacency alive if no further hello is heard.

zebra-rs follows the IOS-XR / RFC model: the operator sets the **hello
interval** (how often we send) and the **hello multiplier** (how many
intervals worth of silence before the receiver declares us dead).
The hold time advertised on the wire is the product:

```
hold_time = hello_interval × hello_multiplier
```

| YANG leaf | Default | Range | Units |
|---|---|---|---|
| `/router/isis/interface/<n>/hello/interval` | 3 | 1..65535 | seconds |
| `/router/isis/interface/<n>/hello/multiplier` | 10 | 2..1000 | (count) |

With the defaults, a router emits a hello every 3 seconds and
advertises a 30-second hold time. The multiplier default of 10 (rather
than IOS-XR's 3) compensates for the shorter default hello interval
(3 s versus IOS-XR's 10 s) — the resulting 30-second hold matches
the conservative end of common deployments.

**Live application.** When either value changes via configuration,
zebra-rs sends `HelloOriginate` for each active level on the
interface. This re-emits a fresh hello PDU (so the new `holdingTime`
hits the wire immediately) and re-arms the periodic timer (so the
new interval takes effect without an adjacency reset).

**Tuning trade-offs.**

- Lowering the interval shortens failure-detection time at the cost
  of more hello traffic and CPU.
- Raising the multiplier without changing the interval makes the
  hello protocol more tolerant of single-packet loss on lossy links
  without changing how often hellos are sent.
- The product (hold time) is what the wire sees; a peer with a
  10-second hello and multiplier 3 expects a 30-second hold from us
  regardless of how we got there.
- Sub-second adjacency detection is typically delegated to BFD rather
  than aggressive hello tuning.

The hold-time multiplication saturates at `u16::MAX` (the on-wire
field's range). Extreme values (e.g. interval 65535 × multiplier 1000)
clamp rather than overflow.

## Hello padding

Hello PDUs are normally padded to the interface MTU so adjacency
formation can detect MTU mismatches early (a too-large hello won't
fit through a smaller-MTU peer and the adjacency never comes up,
which is the desired behaviour — silent black-holing of larger
packets later is far worse).

| YANG leaf | Default | Values |
|---|---|---|
| `/router/isis/interface/<n>/hello/padding` | `always` | `always`, `disable` |

`disable` skips padding entirely. Operationally useful only when
intentionally hiding an MTU mismatch (very rare) or to save a small
amount of bandwidth on extremely high-fanout broadcast LANs.

## Database synchronization — CSNP and PSNP intervals

On broadcast LANs the Designated Intermediate System (DIS) periodically
emits a Complete Sequence Number PDU (CSNP) summarising every LSP it
holds. Receivers compare the summary against their own LSDB and use
Partial Sequence Number PDUs (PSNPs) either to acknowledge already-held
LSPs or to request missing ones. On point-to-point links PSNPs serve
as the explicit per-LSP acknowledgement.

| YANG leaf | Default | Range | Units | Scope |
|---|---|---|---|---|
| `/router/isis/interface/<n>/csnp-interval` | 10 | 1..65535 | seconds | broadcast DIS only |
| `/router/isis/interface/<n>/psnp-interval` | 2 | 1..65535 | seconds | per-interface |

These are best left at default. Stretching `csnp-interval` reduces
periodic LAN overhead but slows recovery of lost LSPs on the segment;
shortening it does the opposite.

**Live application.** Changes apply on the next timer cycle — CSNP
runs only on the DIS and PSNP only while there are pending
acknowledgements, so recreating timers on the fly would mean
cancelling whatever is currently armed for little benefit over
waiting one cycle.

## LSP refresh interval and maximum LSP lifetime

Each self-originated LSP carries a `RemainingLifetime` field counting
down from the maximum lifetime. Routers refresh their own LSPs (bump
the sequence number, reset the lifetime, re-flood) on a periodic
timer that fires before the lifetime would expire on receivers'
LSDBs.

| YANG leaf | Default | Range | Units |
|---|---|---|---|
| `/router/isis/timers/lsp-refresh-interval` | 900 | 1..65535 | seconds |
| `/router/isis/timers/hold-time` (max LSP lifetime) | 1200 | — | seconds |

The naming carries some history. zebra-rs calls the **maximum LSP
lifetime** `hold-time` for the instance-level YANG leaf; IOS-XR's
equivalent command is `max-lsp-lifetime`. Both control the same
value: the `RemainingLifetime` we put on the wire when we originate
or refresh a self-LSP, which receivers count down toward zero.

**Invariant.** The refresh interval must be strictly less than the
maximum lifetime, with enough margin for one refresh round-trip plus
the LSP-zero-age window (60 s) — otherwise our own LSP can age out
on a peer before our refresh reaches them. zebra-rs enforces this in
`insert_self_originate`: the actual scheduled refresh is

```
min(config.refresh_time, lsp.hold_time − 65 s)
```

where the 65-second safety margin combines the ISO 10589 zero-age
lifetime (60 s) and the minimum LSP transmission interval (5 s). If
you shorten `hold-time` aggressively without lowering
`lsp-refresh-interval`, this clamp keeps the refresh timer from
running too late.

**Tuning trade-offs.**

- Raising both `lsp-refresh-interval` and `hold-time` (e.g. 65000 s
  each) reduces background LSP flooding and CPU on very stable
  networks; the trade-off is that stuck routers take longer to age
  out of the database after an ungraceful exit.
- Lowering refresh / lifetime accelerates LSDB cleanup at the cost
  of more flooding traffic.

## min-lsp-arrival-time — storm protection on the receive side

When a peer's LSP arrives with a higher sequence number than the
copy in our LSDB, we install the new version and re-flood. Without
a rate limit a misbehaving neighbour (or a flapping path) can drive
arbitrarily fast LSDB churn and SPF reschedules.

`min-lsp-arrival-time` is a per-LSP receive-side floor: if a new
version of an LSP we already have arrives within the configured
window after the last accepted version of *the same LSP ID*, we
drop the new copy.

| YANG leaf | Default | Range | Units |
|---|---|---|---|
| `/router/isis/timers/min-lsp-arrival-time` | 100 | 1..600000 | milliseconds |

Drop matrix:

| Incoming LSP situation | Action |
|---|---|
| First time we see this LSP ID | Accept |
| Higher seq number, outside window | Accept, refresh per-LSP timestamp |
| Higher seq number, inside window | **Drop** (storm protection) |
| Same or smaller seq number | Drop (RFC 1195 standard rule) |
| Self-originated LSP (insert path) | Window not consulted |

The window is checked per-LSP-ID, not per-sender, so it does not
penalise legitimately fast updates to *different* LSPs during the
same burst. Default matches IOS-XR; values much below 50 ms defeat
the purpose, values above a few hundred milliseconds risk masking
genuinely fast topology changes.

## LSP generation throttle — lsp-gen-interval

Many control-plane events ask us to re-originate our own LSP: a
neighbour adjacency comes up, a per-link metric changes, a prefix
gets added to the redistribution set, a peer floods our own LSP back
at us with a higher sequence number. Without throttling, every
event would trigger an immediate `lsp_generate` → `lsp_emit` →
flood cycle, plus a peer-side SPF reschedule for every reflood.

`lsp-gen-interval` applies the same exponential-backoff algorithm
as `spf-interval` to LSP origination: events that arrive within the
window are coalesced into a single regeneration. The seq-number
floor across coalesced events is folded as `max(existing, new)`, so
the resulting LSP bumps past the highest sequence any peer demanded
during the burst.

| YANG leaf | Default | Range | Units |
|---|---|---|---|
| `/router/isis/lsp-gen-interval/initial-wait` | 50 | 1..120000 | milliseconds |
| `/router/isis/lsp-gen-interval/secondary-wait` | 5000 | 1..120000 | milliseconds |
| `/router/isis/lsp-gen-interval/maximum-wait` | 5000 | 1..120000 | milliseconds |

The IOS-XR-matching default (50 / 5000 / 5000) collapses the
geometric ramp — secondary and maximum are equal, so after the
initial 50 ms response the throttle jumps straight to 5 s spacing
and stays there for the duration of the burst. This reflects the
operational reality that self-LSP origination is expensive (every
regen causes a network-wide reflood and peer-side SPF) and operators
generally prefer conservative spacing once a burst is in progress.

The internal machinery follows the same shape as the SPF throttle:
`Isis::lsp_gen_timer: Levels<Option<Timer>>`,
`Isis::lsp_gen_throttle: Levels<Throttle>`, and
`Isis::lsp_gen_pending_floor: Levels<Option<u32>>` for the
accumulated floor. `LspOriginate` is the front-door message;
`LspGenFire` is the internal "throttle fired, run the work" event.
Both share the generic `Throttle` type defined in
`isis/throttle.rs` (also used by SPF).

## SPF throttle — spf-interval

zebra-rs schedules SPF after any LSDB change that could affect the
shortest-path tree, but coalesces multiple changes that arrive in
quick succession so a single SPF run absorbs a whole topology event.
The coalescing window is governed by the IOS-XR-style exponential
backoff algorithm.

| YANG leaf | Default | Range | Units |
|---|---|---|---|
| `/router/isis/spf-interval/initial-wait` | 50 | 1..120000 | milliseconds |
| `/router/isis/spf-interval/secondary-wait` | 200 | 1..120000 | milliseconds |
| `/router/isis/spf-interval/maximum-wait` | 5000 | 1..120000 | milliseconds |

### Algorithm

The algorithm is best understood as a state machine carrying two
per-level variables: `current_wait_ms` (the wait planned for the
next scheduling event during this burst) and `last_run_at` (the
timestamp of the last SPF completion).

On every `spf_schedule()` event:

1. If a timer is already armed, return — the in-flight SPF will
   absorb this event.
2. Otherwise, decide the wait:
   - If `last_run_at` is `None` (first SPF ever), or
     `now − last_run_at > 2 × maximum-wait` (quiescent period
     elapsed) — reset and use `initial-wait`.
   - Otherwise — use `current_wait_ms` (carried forward from the
     prior event during the same burst).
3. Plan the next wait for any subsequent event during this burst:
   - If we just used `initial-wait`, plan `min(secondary-wait,
     maximum-wait)` next.
   - Otherwise, plan `min(current × 2, maximum-wait)` next
     (saturating multiply).
4. Arm a one-shot timer with the chosen wait. When it fires, SPF
   runs; on completion the SPF handler stamps `last_run_at = now`
   and clears the timer slot.

### Worked example with defaults (50 / 200 / 5000)

```
t=0       topology change → wait 50 ms (initial)
t=50      SPF runs, last_run_at=50, next planned=200
t=70      another change → wait 200 ms (still in burst)
t=270     SPF runs, last_run_at=270, next planned=400
t=300     another change → wait 400 ms
t=700     SPF runs, last_run_at=700, next planned=800
...
                          ... doubles until 5000 cap ...
t+10s     no events for 10 s ( > 2 × 5000 = 10000 ms threshold )
t+10s+1   topology change → wait 50 ms (quiet, reset)
```

### Tuning trade-offs

- **Lowering `initial-wait`** makes isolated changes converge faster
  but increases the chance of running SPF twice for what could have
  been one coalesced run.
- **Raising `maximum-wait`** strengthens storm dampening but extends
  the worst-case time-to-converge during sustained churn. Default
  5 s is the IOS-XR baseline; very stable networks can raise it to
  10 s or more for better CPU economy.
- **Raising `secondary-wait` close to `maximum-wait`** (e.g. setting
  both to 5000 ms) effectively disables the geometric ramp and
  jumps straight from `initial` to `maximum` after the first burst
  event — useful when SPF is genuinely expensive and the operator
  prefers conservative spacing throughout the burst.

### Per-level state

The throttle is independent per level: an event on L1 doesn't
influence L2's wait time and vice versa. The configuration leaves
are currently global (apply to both levels); per-level YANG
qualifiers can be added later if a deployment needs them.

## Summary — default-value reference

| Knob | Default | Scope |
|---|---|---|
| hello interval | 3 s | per-interface |
| hello multiplier | 10 | per-interface |
| hello padding | always | per-interface |
| csnp-interval | 10 s | per-interface |
| psnp-interval | 2 s | per-interface |
| lsp-refresh-interval | 900 s | instance |
| hold-time (max LSP lifetime) | 1200 s | instance |
| min-lsp-arrival-time | 100 ms | instance |
| spf-interval initial-wait | 50 ms | instance |
| spf-interval secondary-wait | 200 ms | instance |
| spf-interval maximum-wait | 5000 ms | instance |
| lsp-gen-interval initial-wait | 50 ms | instance |
| lsp-gen-interval secondary-wait | 5000 ms | instance |
| lsp-gen-interval maximum-wait | 5000 ms | instance |

## Example configurations

### Conservative, low-churn deployment

```
router isis
  timers
    lsp-refresh-interval 1800
    hold-time 7200
    min-lsp-arrival-time 200
  spf-interval
    initial-wait 200
    secondary-wait 1000
    maximum-wait 10000
  interface eth0
    hello
      interval 10
      multiplier 3
    csnp-interval 30
```

Wider hello intervals and longer hold time reduce control-plane
chatter on a network that rarely changes; SPF backs off more
aggressively under any disturbance.

### Aggressive, fast-convergence deployment

```
router isis
  timers
    min-lsp-arrival-time 50
  spf-interval
    initial-wait 20
    secondary-wait 100
    maximum-wait 1000
  interface eth0
    hello
      interval 1
      multiplier 3
```

Sub-second hello / 3-second hold and a 20 ms initial SPF wait
prioritise convergence at the cost of additional control-plane
traffic and CPU. For sub-second adjacency detection in production,
prefer BFD over aggressive hellos.

## Cross-reference — IOS-XR command mapping

| zebra-rs YANG | IOS-XR command |
|---|---|
| `timers/lsp-refresh-interval` | `lsp-refresh-interval` |
| `timers/hold-time` | `max-lsp-lifetime` |
| `timers/min-lsp-arrival-time` | `min-lsp-arrival-time` |
| `spf-interval/{initial,secondary,maximum}-wait` | `spf-interval initial-wait … secondary-wait … maximum-wait …` |
| `lsp-gen-interval/{initial,secondary,maximum}-wait` | `lsp-gen-interval initial-wait … secondary-wait … maximum-wait …` |
| `interface/<n>/hello/interval` | `isis hello-interval` (interface) |
| `interface/<n>/hello/multiplier` | `isis hello-multiplier` (interface) |
| `interface/<n>/hello/padding` | `isis hello-padding` (interface) |
| `interface/<n>/csnp-interval` | `isis csnp-interval` (interface) |
| `interface/<n>/psnp-interval` | `isis retransmit-interval`-adjacent (no exact IOS-XR equivalent — PSNP ack pacing) |

Gaps relative to IOS-XR that zebra-rs does not yet implement:
`prc-interval` (no partial route calculation distinct from full
SPF), `lsp-interval` (LSP send pacing), `retransmit-interval` /
`retransmit-throttle-interval` (no periodic LSP retransmit-until-ack
on point-to-point), `lsp-mtu` (no LSP fragmentation yet),
`adjacency-stagger`, and BFD client integration for IS-IS
adjacencies.
