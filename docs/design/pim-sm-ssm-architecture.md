# PIM-SM/SSM — Overall Architecture & Phasing Plan

Status: **proposal — no code yet** (branch `pim`). This document defines the architecture for
a new PIM-SM/SSM protocol module in zebra-rs, based on a survey of two prior-art
implementations (FRR `pimd`, ZebOS `pimd`/`mribd`) and of zebra-rs's own protocol-module
conventions. It is written so a contributor can resume without the conversation history.

PIM is genuinely greenfield in this tree: there is no mroute socket, no VIF/MFC handling,
no IGMP host-side code, and no `RouteType::Multicast` path anywhere today. The only
adjacent code is EVPN's bridge-MDB/IGMP-*snooping* watch (`RTNLGRP_MDB`), which is L2 and
stays separate.

---

## 1. Goal & scope

Deliver an RFC 7761 PIM Sparse Mode implementation with SSM (RFC 4607) support for IPv4,
integrated as a first-class zebra-rs protocol module:

**In scope (this arc)**

- PIM-SM protocol engine: Hello/neighbors/DR election, Join/Prune (upstream + downstream
  FSMs), Assert, Register/Register-Stop, SPT switchover, (S,G,rpt) prune.
- SSM: `232.0.0.0/8` default range (configurable), (S,G)-only, no RP/register logic.
- IGMPv2/IGMPv3 querier + group/source membership on PIM interfaces.
- Static RP with group-prefix longest-match; BSR (RFC 5059) as a late phase.
- Kernel dataplane: mroute socket (`MRT_INIT`/`MRT_ADD_VIF`/`MRT_ADD_MFC`), upcall
  handling (`NOCACHE`/`WRONGVIF`/`WHOLEPKT`), `pimreg` register VIF.
- RPF via the existing RIB NHT API; VRF support in a late phase (per-VRF instance +
  `MRT_TABLE`).
- YANG config + show commands + tracing subtree + BDD features, per house conventions.

**Out of scope (deferred, see §12)**

IPv6/MLD (pim6), MSDP, AutoRP, PIM-DM/State-Refresh, BFD-for-PIM, MLAG/VxLAN BUM,
mtrace/ssmpingd, IGMP proxy, ECMP rebalance, (\*,\*,RP) state.

---

## 2. RFC surface

| RFC | Role |
|---|---|
| RFC 7761 | PIM-SM (obsoletes 4601) — the core protocol engine |
| RFC 4607 | Source-Specific Multicast (232/8, ff3x::/32) |
| RFC 3376 | IGMPv3 (source-specific membership; required for SSM) |
| RFC 2236 | IGMPv2 |
| RFC 5059 | Bootstrap Router (BSR) — late phase |
| RFC 6226 | PIM group-to-RP mapping rules |
| RFC 3973 | PIM-DM — **non-goal** |
| RFC 4610 / 3618 | Anycast-RP / MSDP — **non-goal** |

---

## 3. Prior art — what we take from whom

Two reference implementations were surveyed in depth: FRR `pimd`
(`../frr/pimd`, monolithic, dual-compiled v4/v6) and ZebOS
(`../Z1/pimd` + `../Z1/mribd`, a three-daemon split where `pimd` is a pure protocol
engine, `mribd` owns kernel MFC/VIF/IGMP, and `nsm` serves RPF lookups over IPC).

**From FRR (behavioral reference — closest to Linux, actively maintained):**

- The kernel dataplane recipe: mroute socket setup (`MRT_TABLE` before `MRT_INIT`,
  `MRT_PIM` for upcalls incl. `WRVIFWHOLE`), VIF-index-vs-ifindex mapping,
  `mfcctl`-shaped OIL shadow, and the four upcalls that drive protocol events
  (`IGMPMSG_NOCACHE` → FHR/first-packet, `WHOLEPKT` → register encapsulation,
  `WRONGVIF` → assert trigger, `WRVIFWHOLE` → SPT switchover at RP/LHR).
  Linux quirks already learned by FRR: (\*,G) MFC requires IIF ∈ OIF list; unresolved
  (S,G) installed with IIF=pimreg so traffic punts until RPF resolves; introspection via
  `/proc/net/ip_mr_vif` and `/proc/net/ip_mr_cache`.
- Timer defaults and FSM behavior details (§10 table below).
- J/P aggregation model: joins/prunes accumulate per RPF-neighbor and flush on the
  periodic J/P timer as one message (FRR `pim_jp_agg.c`).
- The TIB bridge idea (`pim_tib.c`): a thin, explicit seam where IGMP membership becomes
  PIM state — "someone wants G ⇒ add OIF + create local-membership + ref upstream".
- Scope guidance: FRR's own MVP core is instance + interface + neighbor + upstream +
  ifchannel + channel_oil + rpf/nht + tib + IGMP + mroute + static RP + ssm. Everything
  else in pimd (MSDP, MLAG, VxLAN, AutoRP…) is separable.

**From ZebOS (structural reference — cleaner factoring):**

- **Protocol engine isolated from the dataplane.** ZebOS pimd contains zero
  `setsockopt(MRT_*)`; data-plane triggers arrive as typed messages (NoCache, WrongVif,
  WholePkt, StatUpdate). We keep zebra-rs single-process, but reproduce this as a module
  boundary: all kernel mroute I/O lives in `pim/mroute.rs` and talks to the FSM core only
  via the actor's `Message` enum. The FSM core becomes unit-testable without a kernel.
- **RFC macros as named functions.** ZebOS `pim_route.c` implements the RFC 4601/7761
  predicate macros literally (`immediate_olist_sg()`, `inherited_olist_sgrpt()`,
  `join_desired_xg()`, `prune_desired_sgrpt()`…), with cached results in a per-entry
  `macro_state` bitfield. Far more traceable to the spec than FRR's inlined logic. We
  adopt this: `pim/macros.rs` holds pure functions over the TIB, one per RFC macro, and
  each TIB entry caches the last evaluation so state transitions fire on value *change*.
- **Unified TIB.** ZebOS keys (\*,G), (S,G), (S,G,rpt) into one table with typed keys,
  and hangs per-interface downstream state off the entry (vector + VIF bitmaps for
  joined/inherited/pruned/local olists). This maps far better onto Rust ownership than
  FRR's web of back-pointers (`upstream ↔ ifchannel ↔ channel_oil` cross-links), so we
  follow ZebOS here (§6).
- **Explicit FSM tables.** ZebOS assert actions A1–A6 and its DM FSMs are explicit
  state×event dispatch — the template for `match (state, event)` in Rust.
- **Anti-patterns to avoid:** synchronous blocking request/reply toward the dataplane
  (stalls the event loop); `#ifdef`-driven v4/v6 duplication (we keep an AF-clean core
  and add v6 later); management-plane code dwarfing the protocol core.

---

## 4. Position in zebra-rs — process & actor model

PIM is one more actor in the existing single-binary architecture. No new process, no IPC.

- **Spawn:** `ConfigManager::commit_config` gets a `spawn_pim` / `despawn_pim` arm
  (`zebra-rs/src/config/pim.rs`), copied from the `spawn_isis` template
  (`zebra-rs/src/config/isis.rs:7`): idempotency check → `subscribe_to_rib("pim")` →
  `ProtoContext::default_table(rib_client)` → `Pim::new(...)` → `config.subscribe("pim",
  pim.cm.tx)` + `config.subscribe_show("pim", pim.show.tx)` → `inst::serve(pim)` into
  `protocol_tasks`. Despawn sends `rib::Message::ProtoCleanup` (harmless for PIM — we
  install no unicast routes — but keeps the contract) and must also tear down the mroute
  socket (`MRT_DONE`) so the kernel flushes VIFs/MFC.
- **Actor:** top struct `Pim` in `zebra-rs/src/pim/inst.rs` owns `tx/rx:
  mpsc::Unbounded*<Message>`, `cm: ConfigChannel`, `show: ShowChannel`, `rib_rx:
  UnboundedReceiver<RibRx>`, `ctx: ProtoContext`, plus all protocol state. `event_loop()`
  follows the house shape: prime by draining `rib_rx` until `RibRx::EoR` (replays
  links/addresses), then `tokio::select!` over `rib_rx` / `cm.rx` / `show.rx` / `rx`.
- **Sockets feed the channel.** Two reader tasks (house `Task<T>` wrappers, abort-on-drop)
  forward parsed input into the actor as `Message` variants:
  - the per-VRF **PIM socket** (raw IPPROTO_103) → `Message::PimPacket { ifindex, src, dst, packet }`;
  - the per-VRF **mroute socket** (raw IPPROTO_IGMP + `MRT_INIT`) → `Message::Igmp { ... }`
    for IGMP packets and `Message::Upcall(Upcall)` for `struct igmpmsg` kernel upcalls
    (`Upcall::Nocache/Wholepkt/Wrongvif/WrVifWhole { vif, sg, payload }`).
  All FSM work then happens single-threaded inside the actor — no locks.
- **Timers:** every FSM timer is a `context::Timer` (drop-cancels) whose callback sends a
  `Message` (e.g. `Message::JoinTimerExpiry(SgKey)`, `Message::NeighborExpiry(ifindex,
  addr)`, `Message::KeepaliveExpiry(SgKey)`). Never bare `tokio::time` in FSMs.

Message-enum sketch (internal event vocabulary):

```rust
pub enum Message {
    // sockets
    PimPacket { ifindex: u32, src: Ipv4Addr, dst: Ipv4Addr, packet: PimPacket },
    Igmp { ifindex: u32, src: Ipv4Addr, packet: IgmpPacket },
    Upcall(Upcall),                       // kernel igmpmsg, parsed in mroute.rs
    // timers
    HelloTimerExpiry(u32),                // per-interface hello TX
    NeighborExpiry(u32, Ipv4Addr),
    JpPeriodic(Ipv4Addr),                 // per-RPF-neighbor J/P flush
    JoinTimerExpiry(SgKey),
    PrunePendingExpiry(SgKey, u32),
    ExpiryTimer(SgKey, u32),              // downstream ET
    AssertTimerExpiry(SgKey, u32),
    KeepaliveExpiry(SgKey),
    RegisterStopExpiry(SgKey),
    QuerierTimerExpiry(u32),
    // internal recomputation triggers
    RpfUpdate(Ipv4Addr),                  // from RibRx::NexthopUpdate
}
```

---

## 5. Module & crate layout

```
crates/pim-packet/            # new workspace member, modeled on ospf-packet
  src/lib.rs                  # re-exports
  src/parser.rs               # PimPacket + per-type structs (nom-derive, NomBE)
  src/typ.rs                  # PimType: Hello=0 Register=1 RegisterStop=2 JoinPrune=3
                              #          Bootstrap=4 Assert=5 CandRpAdv=8
  src/hello.rs                # Hello TLVs: Holdtime(1) LanPruneDelay(2) DrPriority(19)
                              #             GenerationId(20) AddressList(24)
  src/joinprune.rs            # encoded-unicast/group/source addrs, group records,
                              #   WC/RPT bits — shared by JP + Assert + BSR
  src/checksum.rs             # standard IP checksum; Register checksums header-only
  src/igmp.rs                 # IGMPv2/v3 wire formats (query, v2/v3 reports)
  src/disp.rs                 # Display impls

zebra-rs/src/pim/
  mod.rs
  inst.rs                     # Pim actor: Message enum, new(), event_loop(), serve()
  config.rs                   # callback_build(): "/routing/pim/..." handlers
  show.rs                     # show_build(): show callbacks (text + JSON)
  tracing.rs                  # PimTracing block driven by zebra-pim-tracing.yang
  link.rs                     # PimInterface: per-ifindex state, VIF allocation,
                              #   enable/disable, addr tracking from RibRx
  neighbor.rs                 # hello RX/TX, neighbor table, holdtime, GenID, DR election
  tib.rs                      # SgKey, TibEntry, Tib (the unified table, §6)
  macros.rs                   # RFC 7761 predicates as pure fns over the Tib
  upstream.rs                 # upstream J/P FSM (NotJoined/Joined), join timer,
                              #   RPF′ change / GenID-change handling, SPT-bit logic
  downstream.rs               # per-interface downstream FSM (NoInfo/Join/PrunePending)
                              #   + (S,G,rpt) downstream variant
  jp.rs                       # J/P RX walk + per-RPF-neighbor TX aggregation
  assert_fsm.rs               # NoInfo/Winner/Loser, metric compare, actions A1–A6
  register.rs                 # DR-side register FSM (NoInfo/Join/JoinPending/Prune),
                              #   RP-side register RX / register-stop TX
  rp.rs                       # RpSet: static RP config + group-prefix LPM (+BSR later)
  ssm.rs                      # ssm range predicate (default 232/8, prefix override)
  rpf.rs                      # RPF cache keyed by source/RP addr, backed by RIB NHT
  oil.rs                      # Oil: kernel MFC shadow (iif VIF + oif bitmap + flags)
  mroute.rs                   # ForwardingPlane: mroute socket, MRT_* setsockopts,
                              #   VIF add/del, MFC install/uninstall, upcall parse,
                              #   register encap TX / pimreg handling
  igmp/
    mod.rs                    # per-interface querier state + group/source tables
    v2.rs / v3.rs             # version-specific RX/compat handling
  vrf.rs                      # (late phase) per-VRF spawn, mirroring isis/vrf.rs
```

`crates/pim-packet` follows the `ospf-packet` conventions: `nom = 8` + `nom-derive`
(`NomBE`, `#[nom(Verify)]`, custom `ParseBe`), hand-rolled emitters over
`bytes::BytesMut`, helpers from `crates/packet-utils`. IGMP wire formats live in the same
crate (they share encoded-address helpers and it avoids a second tiny crate).

---

## 6. Core data model

### 6.1 Instance / interface / neighbor

```rust
pub struct Pim {                       // one per VRF (VRF-0 first)
    // actor plumbing: tx/rx, cm, show, rib_rx, ctx, callbacks, show_cb ...
    links: BTreeMap<u32, PimInterface>,        // by ifindex
    tib: Tib,                                  // §6.2
    rp_set: RpSet,                             // static RP LPM (+ BSR later)
    ssm: SsmRange,
    rpf: RpfCache,                             // §8
    fp: ForwardingPlane,                       // mroute socket + VIF/MFC shadow
    jp_agg: BTreeMap<Ipv4Addr, JpBucket>,      // per-RPF-neighbor J/P aggregation
    // timers config (globals): jp_period, keepalive, register_suppress, ...
}

pub struct PimInterface {
    ifindex: u32,
    enabled: bool,                 // config: pim enable
    passive: bool,
    primary: Option<Ipv4Addr>,
    vif: Option<u16>,              // kernel VIF index — allocated, NOT ifindex
    dr: Option<Ipv4Addr>,          // election result; i_am_dr()
    dr_priority: u32,              // default 1
    hello_period: u16,             // default 30s
    holdtime: u16,                 // default 3.5 × hello = 105s
    gen_id: u32,
    neighbors: BTreeMap<Ipv4Addr, Neighbor>,
    hello_timer: Option<Timer>,
    propagation_delay_ms: u16,     // 500
    override_interval_ms: u16,     // 2500
    igmp: IgmpIf,                  // querier + membership state (§9)
}

pub struct Neighbor {
    addr: Ipv4Addr,
    holdtime: u16,
    dr_priority: Option<u32>,      // None ⇒ address-based DR election on this LAN
    gen_id: Option<u32>,
    lan_prune_delay: Option<(u16, u16, bool)>,  // (delay, override, T-bit)
    secondary: Vec<IpAddr>,
    expiry: Timer,
}
```

DR election per RFC 7761 §4.3.2, as in FRR `pim_if_dr_election`: if any neighbor omits
the DR-Priority option, elect by highest address; else highest (priority, address).
A GenID change on an existing neighbor is treated as neighbor bounce: refresh all
upstream state toward that neighbor (triggered J/P) and re-run DR election.

### 6.2 TIB — one table, typed keys (ZebOS-style)

```rust
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SgKey {
    StarG { grp: Ipv4Addr },                      // (*,G)
    Sg    { src: Ipv4Addr, grp: Ipv4Addr },       // (S,G)
    SgRpt { src: Ipv4Addr, grp: Ipv4Addr },       // (S,G,rpt)
}

pub struct Tib {
    entries: BTreeMap<SgKey, TibEntry>,
    // secondary index: group → members, for "walk all state for G" operations
    by_group: BTreeMap<Ipv4Addr, BTreeSet<SgKey>>,
}

pub struct TibEntry {
    key: SgKey,
    // ---- upstream (toward RPF′) ----
    upstream_addr: Option<Ipv4Addr>,  // RP for (*,G); S for (S,G); None if RP unknown
    join_state: JoinState,            // NotJoined | Joined
    join_timer: Option<Timer>,
    reg_state: Option<RegState>,      // (S,G) at DR only: NoInfo|Join|JoinPending|Prune
    spt_bit: bool,                    // (S,G) only
    keepalive: Option<Timer>,         // (S,G): traffic-driven lifetime (KAT)
    // ---- downstream (per interface) ----
    downstream: BTreeMap<u32, Downstream>,   // by ifindex
    // ---- local membership (from IGMP via the TIB bridge) ----
    local: BTreeSet<u32>,                    // ifindexes with IGMP include state
    // ---- cached macro results (fire transitions on change only) ----
    cached: MacroState,               // JoinDesired, PruneDesired(rpt), CouldRegister,
                                      // immediate/inherited olist hash
    // ---- dataplane shadow ----
    oil: Option<Oil>,                 // installed MFC mirror; None = not installed
}

pub struct Downstream {
    state: DsState,                   // NoInfo | Join | PrunePending  (+ rpt variants)
    expiry: Option<Timer>,            // ET
    prune_pending: Option<Timer>,     // PPT
    assert_: AssertState,             // NoInfo | Winner{metric} | Loser{winner, metric}
    assert_timer: Option<Timer>,
    could_assert: bool,               // cached macro
    assert_tracking: bool,            // cached macro
}
```

Design points:

- **No back-pointer web.** The `Tib` is the single owner. (S,G) finds its (\*,G) parent
  by key (`SgKey::StarG { grp }`) at use time — a `BTreeMap` lookup instead of a stored
  reference; this sidesteps every borrow-checker fight that FRR's
  upstream↔ifchannel↔oil graph would cause in Rust.
- **(S,G,rpt) is a real entry** (as in ZebOS), not a flag on (S,G) — downstream rpt-prune
  state and upstream rpt-override behavior differ enough to warrant it.
- **No (\*,\*,RP)** — optional in RFC 7761, absent in FRR, negligible demand.
- **OIL is computed, not maintained incrementally at first.** `macros.rs` implements
  `immediate_olist(sg)`, `inherited_olist(sg)`, `inherited_olist_sgrpt(...)`,
  `join_desired(...)`, `prune_desired_sgrpt(...)` as pure functions; after any input
  event we recompute for the touched entry (and its group siblings), diff against
  `cached`, and fire FSM transitions / MFC updates only on change. This is the ZebOS
  `macro_state` pattern, and it keeps the spec-to-code mapping 1:1. Optimize later if
  profiling demands it.
- **Kernel MFC shadow (`Oil`)** — mirrors `struct mfcctl`: `iif: u16` (VIF), `oifs:
  [u8; MAXVIFS]` TTL array, plus per-OIF provenance flags (`PROTO_PIM`, `PROTO_IGMP`,
  `STAR`) so removing one contributor doesn't strip an OIF another still wants
  (FRR's `oif_flags` lesson).

### 6.3 State machines (all in-actor, `match (state, event)` style)

| FSM | States | Module |
|---|---|---|
| Upstream (\*,G)/(S,G) | NotJoined, Joined (+ JT, override/suppression) | `upstream.rs` |
| Upstream (S,G,rpt) | RPTNotJoined, Pruned, NotPruned (+ OT) | `upstream.rs` |
| Downstream per-if | NoInfo, Join, PrunePending (+ ET, PPT) | `downstream.rs` |
| Downstream (S,G,rpt) | NoInfo, Prune, PrunePending, PruneTmp… | `downstream.rs` |
| Assert per-(entry,if) | NoInfo, IAmWinner, IAmLoser — actions A1–A6 | `assert_fsm.rs` |
| Register (DR, per (S,G)) | NoInfo, Join, JoinPending, Prune | `register.rs` |

Each FSM is a plain function `fn step(state, event, ctx) -> (state, Vec<Action>)` where
`Action` is a small enum (send packet X, start/stop timer Y, update MFC). This keeps
them unit-testable with zero I/O — the direct payoff of the ZebOS-style separation.

---

## 7. Kernel dataplane — `mroute.rs` (`ForwardingPlane`)

All `MRT_*` interaction is confined to this module; the FSM core only sees `Upcall`
messages and calls `fp.install(sg, oil)` / `fp.uninstall(sg)` / `fp.vif_add(ifindex)` /
`fp.vif_del(ifindex)`.

- **Socket:** `socket(AF_INET, SOCK_RAW, IPPROTO_IGMP)` per VRF. Order matters:
  `MRT_TABLE <table_id>` (VRF phase only) **before** `MRT_INIT`; then `MRT_PIM 1` to
  enable PIM-mode upcalls; large recv buffer (FRR uses 8 MB). Wrapped in
  `AsyncFd`, read by a `Task` that forwards into the actor. `MRT_DONE` on despawn.
  This socket also receives all IGMP packets (kernel behavior once `MRT_INIT` is done) —
  it *is* the IGMP RX path; the separate per-interface IGMP concerns are TX + group joins.
- **VIFs:** allocated indices (bitmap allocator), **not** ifindexes; `vifc.vifc_flags =
  VIFF_USE_IFINDEX` with `vifc_lcl_ifindex`. Map both directions
  (`ifindex → vif`, `vif → ifindex`). VIF 0 is reserved for the register VIF
  (`VIFF_REGISTER`, the kernel `pimreg` device), added at instance start.
- **MFC:** `MRT_ADD_MFC` / `MRT_DEL_MFC` with the entry's `Oil` shadow. Known Linux
  quirks to reproduce from FRR:
  - (\*,G) entries (origin `0.0.0.0`) require the IIF to also appear in the OIF list —
    set it in a scratch copy at install time;
  - an (S,G) whose RPF is still unresolved is installed with IIF = register VIF so the
    first packets punt to userspace instead of looping;
  - `PIM_ENFORCE_LOOPFREE_MFC`-style guard: never emit OIF == IIF.
- **Upcalls** (`struct igmpmsg` on the mroute socket, `im_mbz == 0` distinguishes them
  from real IGMP):
  - `IGMPMSG_NOCACHE` — first packet of an unknown (S,G) arrived. If we are DR for the
    source subnet (FHR): create (S,G) with `CouldRegister` evaluation → register FSM.
    For SSM groups: install (S,G) with empty/inherited OIL (join-driven, no register).
  - `IGMPMSG_WHOLEPKT` — full packet punt for register encapsulation: unicast a
    Register (outer IP proto 103, checksum over header only) to RP(G) from the DR.
  - `IGMPMSG_WRONGVIF` — data arrived on a non-IIF interface: assert trigger on that
    interface (§6.3 assert FSM).
  - `IGMPMSG_WRVIFWHOLE` — wrong-VIF **with** full packet: drives Register-Stop TX and
    SPT-bit setting at RP/LHR (SPT switchover). Availability depends on `MRT_PIM`; keep
    FRR's compat path (derive the same events from WRONGVIF + state) if absent.
- **Register decapsulation at the RP is kernel-side:** with `MRT_PIM` on, the kernel's
  PIM code decapsulates Registers and forwards the inner packet through the MFC with
  IIF = register VIF. Userspace (us) only parses the Register copy delivered on the PIM
  socket for protocol actions (create (S,G), send Register-Stop, switch to SPT).
- **Introspection for tests:** `/proc/net/ip_mr_vif`, `/proc/net/ip_mr_cache`,
  `ip mroute show` — BDD assertions will read these.

No `RibType::Pim` / netlink `RouteProtocol` addition is needed for the MVP: PIM installs
MFC entries via the mroute socket, not unicast routes, so `fib/netlink` is untouched.
(If a multicast "MRIB" route type is ever wanted for RPF policy, that's a separate,
later decision — see Open Questions.)

## 7.1 PIM control socket

One raw socket per VRF for IP protocol 103, created via `ctx.raw_socket(...)` — the OSPF
pattern (`zebra-rs/src/ospf/socket.rs`) transfers directly: non-blocking, `IP_PKTINFO`
for ifindex demux, `set_multicast_loop_v4(false)`, TTL 1, TOS internet-control, and a
`join_multicast_v4_n(224.0.0.13, Index(ifindex))` per PIM-enabled interface
(ALL-PIM-ROUTERS). Register/Register-Stop are unicast on the same socket. A single
socket with PKTINFO (house style) replaces FRR's per-interface socket fan-out.

---

## 8. RPF & nexthop tracking

RPF reuses the existing RIB NHT contract — the register-then-gate pattern already proven
by the NHT series:

- `RpfCache` keyed by looked-up address (source S or RP). On first need:
  `ctx.rib.send(rib::Message::NexthopRegister { proto, nh })`; resolution arrives as
  `RibRx::NexthopUpdate { nh, resolution }` and is cached. Entries are refcounted by the
  TIB entries depending on them; `NexthopUnregister` on last drop.
- From a resolution we derive `RpfResult { ifindex, rpf_addr }`:
  - `RPF_interface(S)` = resolved egress ifindex;
  - `RPF′(S,G)` = the resolved nexthop address **if it is a PIM neighbor on that
    interface**; a directly-connected source yields "no upstream neighbor" (FHR case);
    while unresolved or neighbor-less, JoinDesired is gated off (state parks, no J/P).
  - Assert interaction: if the entry is assert-loser on the RPF interface, RPF′ is the
    assert winner (RFC 7761 §4.6) — applied in `macros.rs`, not in the cache.
- On `NexthopUpdate` change: re-run RPF for all dependent TIB entries — this is the
  "RPF′ changed" event: move the entry between per-neighbor J/P buckets (prune old
  neighbor path / join new), update MFC IIF, re-evaluate asserts. Same flow serves
  interface-down and neighbor-loss.
- **URIB only for now.** zebra-rs has no separate multicast RIB; FRR's
  MRIB/URIB lookup-mode matrix is out of scope until a multicast-table feature exists.
- ECMP: take the RIB's selected nexthop as-is (no PIM-side ECMP hash) in the MVP; note
  FRR caveat C3 — the kernel MFC cannot load-split anyway.

---

## 9. IGMP (v2/v3) and the TIB bridge

Lives inside the PIM module (`pim/igmp/`), per interface, FRR-style — *not* in rib. The
existing EVPN `SnoopJoin/SnoopLeave` RibRx events are a different animal (bridge MDB
snooping for VXLAN BUM) and stay untouched.

- **RX:** IGMP packets arrive on the mroute socket (§7). **TX:** queries are sent from a
  small per-interface raw IGMP socket path (router-alert option, TTL 1), joining
  `224.0.0.2` / `224.0.0.22` for querier duties.
- **Querier election:** lowest address wins; other-querier-present timer; startup =
  general query burst. Robustness variable, query-interval, max-response-time
  configurable per interface.
- **State:** per interface, `groups: BTreeMap<Ipv4Addr, GmGroup>` where `GmGroup` holds
  filter mode (INCLUDE/EXCLUDE), per-source entries with source timers, group timer,
  and v2-compat mode (v2 report on the wire demotes the group to EXCLUDE{} handling).
- **The TIB bridge** (one narrow API, FRR `pim_tib.c` distilled):
  - `tib.local_join(sg_or_star_g, ifindex)` — called by IGMP when a group/source becomes
    forwarding-desired on an interface. Creates/refs the TIB entry, sets `local`,
    re-evaluates macros (which may set JoinDesired → upstream Join, add OIF → MFC).
  - `tib.local_prune(sg_or_star_g, ifindex)` — the mirror.
  - SSM enforcement lives at this bridge: an IGMPv3 (S,G) report in the SSM range maps
    to `SgKey::Sg`; an any-source (v2 or v3 EXCLUDE{}) report for an SSM-range group is
    rejected with a rate-limited warning (FRR caveat C19); ASM group reports map to
    `SgKey::StarG`.
- DR gating: only the DR (or sole router) on a downstream LAN adds the OIF/upstream
  state for IGMP-learned membership; non-DR keeps membership state ready for DR
  failover.

---

## 10. RP set & SSM

- `RpSet`: static config entries `{ rp_addr, group_prefix | prefix-list (later) }` in a
  prefix trie; `rp(g) -> Option<Ipv4Addr>` = longest-prefix match; `i_am_rp(g)` checks
  the RP address against local addresses. Provenance field (`Static | Bsr`) from day
  one so BSR (late phase) merges instead of restructuring: static beats BSR for the
  same range (FRR rule); within BSR, RFC 5059 priority + hash.
- `SsmRange`: default `232.0.0.0/8`, overridable by prefix. `is_ssm(g)` is consulted at
  every decision point where SSM semantics diverge: reject (\*,G) join RX, reject
  Register RX, skip register FSM at FHR, no RP resolution, NOCACHE installs join-driven
  state only.
- No RP known for an ASM group ⇒ (\*,G)/(S,G) state can exist (IGMP-driven) but stays
  inactive: nothing installed upstream, MFC parked — mirrors FRR's "dummy OIL" behavior,
  expressed here as `upstream_addr: None` gating JoinDesired.

---

## 11. Config, show, tracing (management surface)

**YANG (config.yang + `zebra-pim.yang` feature module):**

```
routing:                                interface <name>:
  router pim {                            pim {
    rp {                                    enable;            # presence
      static { address A.B.C.D               dr-priority <u32>;
               group <prefix>; ... }          hello-interval <sec>;
    }                                         passive;
    ssm { range <prefix>; }                 }
    join-prune-interval <sec>;              igmp {
    keep-alive-timer <sec>;                   enable;
    register-suppress-time <sec>;             version <2|3>;
    spt-switchover { immediate | never; }     query-interval <sec>;
  }                                         }
```

(Exact shape to be finalized against `config.yang` conventions in the skeleton PR —
the split is the decided part: global knobs under `router pim`, interface enablement
under the interface node, matching how IS-IS/OSPF hang per-interface config.)

- **Callbacks:** `config.rs` `callback_build()` registering `"/routing/pim/..."` and the
  interface-subtree paths, dispatched from `process_cm_msg` exactly like
  `isis/config.rs:48`. React to `Set/Delete`; reconcile at `CommitEnd` (e.g. interface
  set diffing → VIF add/del, socket group joins).
- **Spawn wiring:** `config/manager.rs` gets the `spawn_pim` arm; `show_proto()` gets an
  `is_pim` matcher; `exec.yang` gets `container pim` under show.
- **Show commands** (text + `json` flag threaded per house convention):
  `show pim interface`, `show pim neighbor`, `show pim rp-info`,
  `show pim upstream`, `show pim join` (downstream state), `show pim state`,
  `show mroute` (TIB + kernel MFC counters via `MRT` stats / `/proc`),
  `show igmp interface`, `show igmp groups [detail]`.
- **Tracing:** `zebra-pim-tracing.yang` + `pim/tracing.rs` with the house presence-
  container pattern: categories `hello`, `join-prune`, `register`, `assert`, `igmp`,
  `mroute` (upcalls/MFC), `rp`, each with direction/level, plus `all`.

**Cross-cutting touchpoint checklist** (the complete out-of-module diff):
workspace `Cargo.toml` member + `zebra-rs/Cargo.toml` dep (`pim-packet`);
`main.rs` `mod pim;`; `config/manager.rs` spawn/despawn + `show_proto` + `is_pim`;
`config/pim.rs`; `config.yang` + `exec.yang` + `zebra-pim.yang` + `zebra-pim-tracing.yang`.
Nothing in `rib/` or `fib/` changes for the MVP.

---

## 12. Timers & defaults (RFC 7761 / FRR-aligned)

| Timer / constant | Default | Notes |
|---|---|---|
| Hello period | 30 s | triggered-hello delay 5 s; hello before first J/P on a new iface |
| Neighbor holdtime | 105 s | 3.5 × hello |
| DR priority | 1 | option omitted ⇒ LAN falls back to address election |
| Propagation delay / override interval | 500 ms / 2500 ms | LAN Prune Delay option; J/P override window |
| J/P period | 60 s | per-RPF-neighbor aggregated send |
| J/P holdtime | 210 s | 3.5 × period; drives downstream ET |
| Keepalive (KAT) | 210 s | (S,G) traffic-driven lifetime; RP variant 3×suppress+probe |
| Register suppress / probe | 60 s / 5 s | probe randomized ~0.5–1.5× in FRR |
| Assert time / override | 180 s / 3 s | |
| IGMP query interval / max response | 125 s / 10 s | robustness 2 |

All defaults become YANG-configurable knobs under `router pim` (global) or the
interface subtree, but ship with these values.

---

## 13. End-to-end flows (sanity walkthroughs)

**Receiver joins (ASM, we are LHR/DR):** IGMPv3 report for G → `igmp/` updates group
state → `tib.local_join(StarG{g}, if)` → macros: JoinDesired(\*,G) false→true →
upstream FSM NotJoined→Joined → RPF(RP(G)) via NHT → Join(\*,G) queued in the RPF
neighbor's `JpBucket`, JT started → OIL gains the receiver OIF → MFC (\*,G) installed
(IIF = RPF(RP) VIF, IIF forced into OIF per kernel quirk).

**Source starts (we are FHR/DR):** first packet → kernel `NOCACHE` upcall → (S,G)
entry, `CouldRegister` true → register FSM Join: MFC (S,G) installed with register VIF
in OIL → kernel punts `WHOLEPKT` per packet → Register unicast to RP → RP creates
(S,G), joins SPT toward S → native traffic reaches RP → RP sends Register-Stop → FHR
register FSM → Prune (suppression timer, NULL-registers as probes).

**SPT switchover (LHR):** first native packet down the RPT for (S,G) with local
receivers → LHR policy `spt-switchover immediate` → (S,G) JoinDesired → join SPT;
when traffic arrives on the SPT IIF, SPT-bit set (Update_SPTbit rules) → (S,G,rpt)
PruneDesired → SGrpt prune rides the next (\*,G) J/P toward the RP.

---

## 14. Phasing (smallest meaningful PR each; one branch/PR at a time)

| Phase | Deliverable | Proof |
|---|---|---|
| 1 | `crates/pim-packet`: header, Hello TLVs, Join/Prune, Assert, Register/Register-Stop, IGMP v2/v3 formats; checksums | unit tests with wire fixtures (FRR pcap-derived) |
| 2 | Module skeleton: spawn arm, YANG (`router pim` + interface `pim enable`), actor, PIM socket, Hello TX/RX, neighbor table, DR election, `show pim interface/neighbor`, tracing | BDD: 2-ns neighbor-up, DR election, holdtime expiry, GenID bounce |
| 3 | IGMP v2/v3: querier election, group/source state, `show igmp ...` (no PIM coupling yet) | BDD: ns receiver joins group (socat/python), `show igmp groups` asserts |
| 4 | Dataplane + SSM slice: mroute socket, VIF/MFC, upcalls, TIB + macros, upstream/downstream J/P FSMs, RPF via NHT, J/P aggregation. SSM (S,G) end-to-end | BDD: 3-ns chain, IGMPv3 (S,G) join at LHR, sender pings 232.x — receiver sees traffic; `ip mroute` shows (S,G) on transit |
| 5 | ASM with static RP: RP LPM, (\*,G), register FSM both sides, Register-Stop, KAT, SPT switchover + SGrpt prune | BDD: 4-ns (src—FHR—RP—LHR—rcv): register path, native path after switchover, `show pim upstream` SPT-bit |
| 6 | Assert FSM + WRONGVIF; LAN behaviors: join suppression, prune override (LAN Prune Delay) | BDD: LAN topology (bridge ns) with two upstream routers, assert winner/loser converges |
| 7 | VRF: per-VRF instance (`MRT_TABLE`), `vrf.rs` mirroring `isis/vrf.rs`, `show ... vrf` | BDD: VRF-scoped SSM forwarding |
| 8 | BSR (RFC 5059): C-BSR election, BSM flood/RPF check, C-RP advertisement, RP-set merge under static-beats-dynamic | BDD: BSR-elected RP serves ASM joins |

Every BDD feature ends with the mandatory `Scenario: Teardown topology`. Traffic
verification uses namespace-local senders (`ping -I <if> 232.x.y.z`) and IGMP-joining
receivers (socat/python) plus `/proc/net/ip_mr_cache` / `ip mroute` assertions —
mirroring how existing features assert kernel state.

Follow-the-house-rules note: confirm direction with the smallest PR first (Phase 1 crate
is intentionally standalone and risk-free), `cargo fmt` before every commit, workspace
clippy, full test suite before push.

---

## 15. Deferred / non-goals (explicit)

| Item | Why deferred |
|---|---|
| IPv6 PIM + MLD | Core is AF-clean (SgKey/oil/macros generic-ready) but v4 ships first; v6 needs MRT6, MLDv2, embedded-RP — its own arc (IS-IS v4/v6 dedup showed retrofit is tractable) |
| MSDP / Anycast-RP | Inter-domain ASM; TCP peering, SA caches — separate arc |
| AutoRP | Cisco-proprietary; BSR is the standards-track mechanism |
| PIM-DM / State-Refresh | Different protocol personality; SM/SSM covers deployments we target |
| BFD for PIM neighbors | House BFD client pattern exists (`ClientReq::Subscribe`); bolt-on later |
| MLAG / VxLAN BUM / EVPN coupling | Interacts with cradle/EVPN work; revisit after core lands |
| mtrace, ssmpingd, IGMP proxy | Diagnostics/edge features |
| ECMP rebalance, MRIB lookup modes | Needs multicast-table support zebra-rs lacks |

---

## 16. Open questions (to settle in the Phase-2 PR review)

1. **Interface config spelling** — `interface e0 { pim { enable } igmp { enable } }` vs
   `ip pim`/`ip igmp` prefixes: match whichever per-interface protocol convention
   `config.yang` uses at the time of the skeleton PR.
2. **`show mroute` counters** — poll `MRT` stats via `SIOCGETSGCNT`/`/proc` on demand
   (show-time) vs periodic stat timer updating the TIB. Proposal: on-demand at show
   time; add a poller only if KAT accuracy needs it (FRR polls via its timer wheel —
   revisit when implementing KAT: KAT refresh needs *some* traffic signal, either
   `SIOCGETSGCNT` polling or upcall-driven; decide with measurements in Phase 5).
3. **IGMP TX socket** — reuse the mroute socket for query TX vs a dedicated TX socket
   with router-alert; decide at Phase 3 based on what the kernel permits cleanly.
4. **SPT switchover policy surface** — `immediate | never` first (FRR effectively does
   immediate); packet/byte-threshold policies later if requested.
