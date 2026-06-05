# BGP Tracing — Consistency-with-IS-IS Plan

Plan to rework BGP debug/tracing so it matches the conditional-tracing
pattern already used by IS-IS (and OSPF). This is a design + proposal
doc: it captures the current state of all three protocols, the gaps,
the target architecture (Rust + YANG), and a phase-by-phase slice so a
contributor can pick it up without the conversation history.

Read this first if you're touching `zebra-rs/src/bgp/tracing.rs`,
`zebra-rs/src/bgp/debug.rs`, the `/router/bgp/debug` callback in
`zebra-rs/src/bgp/config.rs`, or anything under `zebra-rs/yang/zebra-bgp-*.yang`.

Reference implementations to mirror:

- `zebra-rs/src/isis/tracing.rs` — `IsisTracing` struct, `should_trace_*`
  gates, conditional macros.
- `crates/isis-macros/src/lib.rs` — `#[isis_pdu_handler(Type, Direction)]`
  attribute macro.
- `zebra-rs/src/isis/config.rs` — `tracing_add()` callback wiring.
- `zebra-rs/yang/config.yang` (`container tracing` at ~line 2106) — the
  IS-IS YANG schema.
- `zebra-rs/src/ospf/tracing.rs` — second instance of the same pattern,
  confirming it is the house style.

## Status (2026-06-05)

**Not started — analysis only.** No BGP code changed by this plan yet.
The only committed change on the `feature/bgp-tracing-consistency`
branch so far is an unrelated FIB log-level downgrade
(`fib/netlink/handle.rs`: `RTNLGRP_NEXTHOP` join `info!`→`debug!`).

## The reference pattern (IS-IS / OSPF)

Both interior protocols implement *conditional tracing*: a typed config
struct lives on the running instance, config callbacks mutate it, and
gated macros consult it before emitting a `proto`-tagged event.

- **Config struct** — `IsisTracing { packet, event, fsm, database }`,
  each a small typed sub-config (e.g. `PacketConfig { enabled,
  direction, level }`). Lives on the `Isis` instance, exposed to packet
  code via `top.tracing` (`IsisTop.tracing: &IsisTracing`).
- **Gating** — `should_trace_packet(type, dir, level)`,
  `should_trace_event(...)`, `should_trace_database(...)`.
- **Conditional macros** — `isis_packet_trace!`, `isis_event_trace!`,
  `isis_database_trace!`, plus `isis_pkt_trace!` / `isis_pdu_trace!`
  that use handler-injected constants. Each gates on `should_trace_*`
  then emits `tracing::info!(proto = "isis", category = …, …)`.
- **Plain proto macros** — `isis_info! / warn! / error! / debug! /
  trace!` add `proto = "isis"` and are used throughout (~3 info plus
  ~40 conditional invocations across the IS-IS tree).
- **Proc-macro helper** — `crates/isis-macros` `#[isis_pdu_handler(Hello,
  Recv)]` injects `_ISIS_PKT_TYPE` / `_ISIS_PKT_DIR` constants so the
  per-handler macros need no repeated arguments.
- **YANG** — `container tracing` under `/router/isis` in `config.yang`:
  `all` boolean + `packet` / `event` / `fsm` / `database` lists keyed by
  `type`, with `direction` (send/receive/both) and `level`
  (level-1/level-2/both) leaves.
- **Config wiring** — `isis/config.rs` `tracing_add("/packet" | "/event"
  | "/fsm" | "/database")` registers callbacks that mutate
  `isis.tracing.*`. Because the config tree node exists in YANG, the
  state persists in running-config and tab-completes.

OSPF replicates this exactly (`OspfTracing`, `container tracing` at
`config.yang:784`, `tracing_add` in `ospf/config.rs`).

## Current BGP state

BGP has the *names* of a tracing system but none of the wiring works:

- `bgp/debug.rs` — `BgpDebugFlags`, a flat-bool struct (`event, update,
  open, notification, keepalive, fsm, graceful_restart, route, policy,
  packet_dump`) with `enable_all` / `disable_all`.
- `bgp/tracing.rs` — plain `bgp_info! / warn! / error! / debug! /
  trace!` (add `proto = "bgp"`) plus `bgp_debug_cat!`.
- `bgp/config.rs` — `config_debug_category()` maps a `category` string
  to a `BgpDebugFlags` field, registered at `/router/bgp/debug`
  (`config.rs:2008`).

### What is broken / dead

1. **No YANG node** exists for `/router/bgp/debug`. BGP's top-level
   container is `bgp:bgp` (from `ietf-bgp`), extended only by
   `augment` in `zebra-bgp-*.yang`; nothing defines a `debug` (or
   `tracing`) child. libyang therefore rejects `set router bgp debug …`,
   so the registered callback is unreachable.
2. **Nothing reads `BgpDebugFlags`.** Even if the callback fired, no
   code path consults the flags — there is no `should_trace_*` and no
   gated macro that reads them.
3. **`bgp_debug_cat!` cannot compile.** It calls
   `$bgp.debug_flags.is_enabled($cat)`; `BgpDebugFlags` has no
   `is_enabled` method. It survives only because it is invoked nowhere.
4. **The `bgp_*` proto macros are invoked 0 times.** All BGP logging
   uses bare `tracing::info!/warn!/…`, most *without* `proto = "bgp"`,
   so BGP logs are not reliably filterable by protocol — unlike IS-IS /
   OSPF.

### Gap summary

| Capability | IS-IS / OSPF | BGP today |
| --- | --- | --- |
| Typed, nested tracing config | yes | flat bools |
| `should_trace_*` gating | yes | none |
| Conditional macros (used) | yes (~40) | none (0) |
| `proto="bgp"` on every log | yes | rarely |
| Per-packet direction filter | yes | none |
| YANG schema node | yes | **none** |
| Reachable config callback | yes | **no** (orphaned) |
| Appears in running-config | yes | no |
| Proc-macro handler helper | yes | none |
| Verb | `tracing` | `debug` |

## Proposal — Rust

Retire `BgpDebugFlags`; build `BgpTracing` in `bgp/tracing.rs` shaped
like `IsisTracing` but BGP-specific (no L1/L2 `level` dimension):

```text
BgpTracing {
    all: bool,
    packet: PacketTracing {
        open, update, notification, keepalive, route_refresh:
            PacketConfig { enabled, direction },   // direction: Send|Recv|Both
        all: bool,
    },
    fsm: FsmTracing {
        session: FsmConfig { enabled, detail },    // BGP has one per-peer FSM
    },
    event: EventTracing {
        graceful_restart, route, policy: EventConfig { enabled },
        all: bool,
    },
}
```

- Add `should_trace_packet(type, dir)`, `should_trace_fsm(type,
  detail)`, `should_trace_event(type)`.
- Add gated macros `bgp_packet_trace!` / `bgp_fsm_trace!` /
  `bgp_event_trace!` that gate then emit `tracing::info!(proto = "bgp",
  category = …, …)` — same shape as `isis_*_trace!`.
- **Delete `bgp_debug_cat!`** (broken) and `bgp/debug.rs`.
- Keep `bgp_info!/warn!/error!/debug!/trace!` and actually adopt them
  across `bgp/` (convert bare `tracing::*`) so every BGP log carries
  `proto = "bgp"`.
- **Placement:** put `tracing: BgpTracing` on the `Bgp` instance. The
  central dispatch `Bgp::process_msg` (`bgp/inst.rs:977`) already holds
  `&mut Bgp` and even has the commented-out per-packet `tracing::info!`
  lines for `BGPOpen` / `UpdateMsg` / `KeepAliveMsg` — that is exactly
  where `bgp_packet_trace!(self.tracing, …)` goes. Only if a trace site
  sits deep inside `&mut Peer` FSM code do we snapshot `BgpTracing` onto
  `Peer`, reusing the existing `adv_interval` snapshot pattern in
  `bgp/timer.rs`.
- **Optional / deferred:** a `#[bgp_pdu_handler(Update, Recv)]`
  attribute (new `crates/bgp-macros`, or a shared crate). BGP dispatch
  is centralized, so the IS-IS per-handler-constant trick buys little —
  defer unless packet tracing ends up spread across many handlers.

## Proposal — YANG

BGP is *not* in `config.yang`'s `router` container, so the IS-IS
approach of editing `config.yang` inline does not apply. Instead follow
the established BGP augmentation pattern (`zebra-bgp-timer.yang`):

- **New file `zebra-bgp-tracing.yang`** that does
  `augment "/configure:set/config:router/bgp:bgp"` and the matching
  `delete` augment, adding a `container tracing`. Wire its import into
  `configure.yang` like the other `zebra-bgp-*` modules. (CI's
  `yang_load_tests` validates this — cargo/clippy do not.)
- Schema (mirror IS-IS `container tracing`, drop `level`):

```yang
container tracing {
  ext:help "BGP debug tracing";
  leaf all { type boolean; }
  list packet {
    key "type";
    leaf type { type enumeration {
      enum open; enum update; enum notification;
      enum keepalive; enum route-refresh; enum all; } }
    leaf direction {
      type enumeration { enum send; enum receive; enum both; }
      default both;
    }
  }
  list fsm {
    key "type";
    leaf type { type enumeration { enum session; enum all; } }
    leaf detail { type boolean; default false; }
  }
  list event {
    key "type";
    leaf type { type enumeration {
      enum graceful-restart; enum route; enum policy; enum all; } }
  }
}
```

- **Drop** the orphaned `/router/bgp/debug` callback (`config.rs:1719`
  + the `callback_add` at `config.rs:2008`) and `BgpDebugFlags`.
- Register `/router/bgp/tracing/{packet,fsm,event}` callbacks the way
  `isis/config.rs` does (a `tracing_add` helper rooted at
  `/router/bgp/tracing`).

Resulting CLI, consistent with `router isis`:

```text
router bgp 65000
 tracing all
 tracing packet update direction receive
 tracing fsm session detail
 tracing event graceful-restart
```

**Verb change `debug` → `tracing`** is recommended for internal
consistency and costs nothing: the `debug` form is currently
unreachable, so there is no working command to migrate.

## Open decisions

1. **CLI verb** — `tracing` (internal consistency; recommended) vs keep
   `debug` (FRR-operator familiarity).
2. **Scope** — IS-IS/OSPF trace globally per instance. Keep BGP global
   for parity (recommended for the first slice), or add an optional
   per-neighbor scope later.
3. **Shared core (future)** — `IsisTracing` and `OspfTracing` already
   duplicate the packet/direction/fsm scaffolding; a later refactor
   could factor a generic `crate::tracing` core that BGP also uses. Out
   of scope here per "smallest PR first" — BGP should match the existing
   per-protocol pattern now.

## Phase slice

| Phase | Scope |
| --- | --- |
| 1 | `bgp/tracing.rs`: `BgpTracing` struct + `should_trace_*` + gated macros; delete `bgp_debug_cat!` and `bgp/debug.rs`; `tracing: BgpTracing` field on `Bgp`. No behavior change yet. |
| 2 | `zebra-bgp-tracing.yang` + `configure.yang` import; replace `/router/bgp/debug` callback with `/router/bgp/tracing/*` callbacks in `bgp/config.rs`. Command becomes reachable + persists in running-config. |
| 3 | Wire the commented-out packet logs in `Bgp::process_msg` to `bgp_packet_trace!`; add `bgp_fsm_trace!` at FSM transitions and `bgp_event_trace!` for graceful-restart / route / policy. |
| 4 | Sweep bare `tracing::*` calls in `bgp/` over to `bgp_info!/warn!/…` so all BGP logs carry `proto = "bgp"`. |
| 5 (optional) | `crates/bgp-macros` `#[bgp_pdu_handler]` only if packet tracing ends up spread across many handlers. |
```