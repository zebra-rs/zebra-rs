# STAMP Phase 1 — Step-by-Step Implementation Plan

> **Status:** implementation plan, awaiting review (2026-06-12)
> **Parent doc:** [stamp-sr-mpls-te-plan.md](./stamp-sr-mpls-te-plan.md) — this document turns its
> "Phase 1 — Link TE metrics" row into concrete, ordered steps against the current tree.
> **Branch:** `stamp-phase1`

---

## 1. Scope

Phase 1 closes the loop **probe → stats → damping → IGP `te-metric` → LSP/LSA → Flex-Algo SPF**
for IPv4 point-to-point links, in both IS-IS and OSPFv2:

- New `zebra-rs/src/stamp/` task: RFC 8762 unauthenticated Session-Sender + per-session stats,
  damping, and a BFD-style client API.
- A **minimal implicit Session-Reflector** for registered IGP sessions (deviation from the parent
  plan, see §2).
- IGP hooks: register a session when a P2P adjacency reaches Up/Full, store the measured
  snapshot on the link, merge static-over-measured at origination.
- Config: `te-metric { measurement { enable; interval; damping-period; } }` on IS-IS and
  OSPFv2 interfaces.
- Show: `show stamp`, `show stamp session`, `show stamp statistics`.
- Tests: unit (stats/damping/timestamp/reflector), in-process loopback integration test,
  one BDD feature, YANG parse pins.

**Out of scope (deferred, per parent plan):** configured external-facing reflector
(`services monitoring stamp`), LAN circuits, IPv6 sessions, RFC 8972 TLVs / RFC 9503 return
path, authenticated modes, loss export to the IGP, VRF sessions, OSPFv3.

---

## 2. Deviation from the parent plan: implicit reflector in Phase 1

The parent plan defers the reflector to Phase 2. But with **no** reflector, two zebra-rs
routers cannot measure each other — Phase 1's "close the loop on a lab topology" goal and any
BDD would require an external Cisco/Juniper reflector. So Phase 1 ships a minimal **stateless**
reflector with an **implicit allow-list**: the wildcard `0.0.0.0:862` socket reflects a probe
only when its source IP matches the remote address of a *registered* session (i.e. measurement
is enabled on both ends of the link — the Cisco SR-PM model). The Phase-2 item stays: the
*configured* 4-tuple allow-list for external controllers.

---

## 3. Design decisions (locked before coding)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Delay = `((T4−T1) − (T3−T2)) / 2` µs | RFC 8762 four-timestamp two-way delay; the `(T3−T2)` reflector-residence term uses only the peer's clock, so clock offset cancels. No clock-sync requirement. Discard samples that compute negative or > 10 s (wall-clock step guard). |
| D2 | Timestamps: NTP 64-bit format, `Z=0`, `S=0` (unsynced) | RFC 8762 §4.6 default; TWAMP-Light interop per parent plan §9. From `SystemTime` (+2208988800 s epoch shift). |
| D3 | Per-session **connected** UDP sender socket, ephemeral source port, dst 862 | Kernel does reply demux per 4-tuple; no SSID-based global demux needed. Source IP = the link address from the session key (bind). TTL 255 on egress. |
| D4 | One wildcard reflector socket `0.0.0.0:862`, `IP_RECVTTL` + `IP_PKTINFO`, replies via `sendmsg` stamping src addr = probe's dst, egress pinned to ingress ifindex | Mirrors `bfd/socket.rs` + `bfd/network.rs` exactly; reply source must equal the probed address for the sender's connected-socket demux to accept it. |
| D5 | Stateless reflector mode: reflected `seq` = sender `seq`; `ssid` echoed; RFC 6038 symmetric size via Extra-Padding TLV when the request is longer than the 44-octet base | RFC 8762 §4.3; stateful (directional loss) is Phase 4 in the parent plan. |
| D6 | Stats window = samples accumulated per damping period; snapshot = `{min, max, avg, variation}`; `variation` = mean absolute difference of consecutive samples | Min/max are what Flex-Algo metric-type 1 and sub-TLV 28/34 need (parent plan §6); avg fills `unidirectional-delay`, variation fills sub-TLV 29/35. |
| D7 | Damping: at each period tick, export iff (first export) or (clear) or any field moved by more than `max(old/10, 50 µs)` | Suppresses LSP/LSA churn from µs-noise on stable links; the absolute floor stops sub-500 µs links from re-originating every period. Constants in `damping.rs`, config knobs later if needed. |
| D8 | A period with **zero** samples after a previous export ⇒ export `None` (clear) | Measured values must not go stale when the peer stops reflecting; clearing withdraws the sub-TLVs so the link is pruned from metric-type-1 topology (RFC 9350 §15) or falls back to static config. |
| D9 | Loss: `sent`/`received` counters kept per window for `show stamp`, **not** exported to the IGP | Per parent plan §6 — loss needs stateful tracking for accuracy; a 30-sample window is too noisy to advertise. |
| D10 | Merge precedence at origination: **static config field wins over measured, per field** | Parent plan §7.4 recommendation — operator override. Implemented as `te_metric_effective()` on the link, never mutating `config.te_metric`. |
| D11 | Sessions are shared across protocols: one `SessionKey {local, remote, ifindex}`, BFD-style `subscribers: HashMap<SessionKey, BTreeMap<ClientId, notifier>>` | IS-IS and OSPF on the same link measure once; both get `MetricUpdate`s. First Subscribe creates the session with its params; a later Subscribe with different params retunes the live probe/export timers (documented last-writer-wins, cheaper than BFD's Poll-Sequence constraint). |
| D12 | `stamp` task is **eager-spawned** in the `router ospf` / `router isis` arms of `commit_config`, before `spawn_ospf` / `spawn_isis`; despawned when neither proto remains in candidate | Identical to BFD: the IGPs capture `stamp_client_tx` by value at spawn (`config/manager.rs:487-535` pattern, despawn block at `:627-640`). Port-862 bind failure is non-fatal (`warn!`, task not inserted — same as `spawn_nd`). |
| D13 | IPv4 sessions only; IS-IS derives the pair from `v4addr` × neighbor `addr4`, OSPF from `V::bfd_addrs` (v2: v4 pair, v3: `None`) | Mirrors BFD's history (v6 was a follow-up series). `SessionKey` already holds `IpAddr` so v6 is additive later. A v6-only IS-IS adjacency simply forms no session. |
| D14 | P2P circuits only (`is_p2p()` / `network_type == PointToPoint`) | Parent plan Phase 1 row; LAN neighbor addressing is Phase 2. |
| D15 | VRF children pass `stamp_client_tx = None` | Sessions are default-VRF only in Phase 1; a VRF session needs a per-VRF 862 socket (`SO_BINDTODEVICE`), deferred. |
| D16 | SSID: nonzero, table-allocated u16 per session, validated on replies | Cheap integrity check on top of the connected-socket demux. |

---

## 4. Step-by-step plan

### Step 0 — Branch + dependency

1. Branch `stamp-phase1` off `main` (done).
2. `zebra-rs/Cargo.toml`: add `stamp-packet = { path = "../crates/stamp-packet" }`.
   The crate is complete for our needs (verified): `SenderPacket`/`ReflectorPacket`
   `parse`/`emit`, `StampTimestamp{seconds,fraction}`, `ErrorEstimate{synced,format,scale,multiplier}`,
   `TimestampFormat::Ntp`, `StampTlv::ExtraPadding`, `STAMP_UDP_PORT = 862`, `BASE_LEN = 44`.

### Step 1 — `zebra-rs/src/stamp/` core module

New files, mirroring `bfd/` file-for-file where a sibling exists:

| File | Contents |
|------|----------|
| `mod.rs` | module decls + `#[cfg(test)] mod integration;` (narrow `#[allow(dead_code)]` only if needed, with comment — repo convention) |
| `timestamp.rs` | `now_ntp() -> StampTimestamp` (UNIX→NTP epoch shift 2 208 988 800 s, fraction = ns·2³²/10⁹); `delta_micros(later, earlier) -> i64`; unit tests (round-trip, fraction math, negative delta) |
| `session.rs` | `SessionKey { local: IpAddr, remote: IpAddr, ifindex: u32 }` (Ord/Hash/Copy); `SessionParams { interval_ms: u32, damping_secs: u32, dst_port: u16 }` (+ `Default` = 1000 / 30 / 862, `PartialEq` for diff-gating); `MeasurementConfig { enable, interval_ms, damping_period_secs }` (the YANG mirror both IGPs embed, with `resolve() -> SessionParams`); `Session` (key, params, ssid, next_seq, sender sock `Arc<AsyncFd<Socket>>`, counters `tx/rx/rx_invalid`, `StatsWindow`, `Damping`, `last_export: Option<MetricSnapshot>`, `last_rx: Option<Instant>`, created `Instant`); `SessionTable` (BTreeMap by key + nonzero-u16 ssid allocator) |
| `stats.rs` | `MetricSnapshot { min, max, avg, variation: u32 }` (µs); `StatsWindow { delays: Vec<u32>, sent: u32, received: u32 }` with `record_*`, `snapshot() -> Option<MetricSnapshot>`, `reset()`, `loss_pct()`; unit tests |
| `damping.rs` | `Damping { last: Option<MetricSnapshot> }`; `should_export(new: Option<&MetricSnapshot>) -> bool` per D7/D8; `const THRESHOLD_DIVISOR: u32 = 10; const THRESHOLD_FLOOR_US: u32 = 50;` unit tests (suppressed / fired / first / clear) |
| `socket.rs` | `stamp_reflector_socket(ctx, bind: SocketAddrV4)` — UDP via `ctx.udp_socket_unbound`, nonblocking, reuse, TTL 255, `IP_RECVTTL`, `IP_PKTINFO`, bind (copy of `bfd_socket_ipv4`, `bfd/socket.rs:38-49`); `stamp_sender_socket(ctx, local: SocketAddrV4, remote: SocketAddrV4)` — UDP, nonblocking, TTL 255, bind `(local_ip, 0)`, `connect(remote)` |
| `network.rs` | `reflector_read(sock, tx)` — `recvmsg` loop with `Ipv4PacketInfo` + `Ipv4Ttl` cmsgs (copy of `bfd/network.rs:48-109`), parses `SenderPacket`, stamps `rx_ts = now_ntp()` at receipt, sends `Message::ProbeRecv{probe, src, dst, ifindex, ttl, rx_ts}`; `ReflectRequest { reply: ReflectorPacket, dst: SocketAddr, src: Option<IpAddr>, ifindex: Option<u32> }` + `reflector_write(sock, rx)` — `sendmsg` with `in_pktinfo` (copy of `bfd/network.rs:117-166`); `sender_read(key, sock, tx)` — plain `recv` on the connected socket, parses `ReflectorPacket`, stamps T4, sends `Message::ReplyRecv{key, reply, t4}` |
| `sender.rs` | `session_prober(key, params, cmd_rx, main_tx)` — one tokio task per session driving two `tokio::time::interval`s (probe tick → `Message::TxTick{key}`, export tick → `Message::ExportTick{key}`) and a `ProberCmd { Retune(SessionParams), Shutdown }` channel; `ProberHandle { cmd_tx, _task: Task<()> }` |
| `reflector.rs` | `build_reply(probe: &SenderPacket, rx_ts, ttl, req_len) -> ReflectorPacket` — stateless copy semantics per D5, symmetric-size padding; unit tests (field copies, padding size, sub-4-byte-pad skip) |
| `client.rs` | `ClientId = String`; `ClientReq::{Subscribe{client,key,params,notifier}, Unsubscribe{client,key}}`; `ClientReqChannel` (copy of `bfd/inst.rs:87-103`); `StampEvent::MetricUpdate { key, snapshot: Option<MetricSnapshot> }` (`None` = clear, D8) |
| `inst.rs` | `Stamp` struct: `rx`, `sessions`, `cm: ConfigChannel`, `show: ShowChannel`, `show_cb`, `client_req`, `subscribers`, `main_tx`, `reflect_tx`, `probers: HashMap<SessionKey, ProberHandle>`, reflector counters, `local_addr` (test introspection); `Message::{ProbeRecv, ReplyRecv, TxTick, ExportTick}`; `new(ctx)` binds 862 / `new_with(ctx, bind)` for tests; `subscribe`/`unsubscribe`/`process_client_req` (subscribe mirrors current `last_export` to the new subscriber, BFD-style); `on_tx_tick` (build `SenderPacket`, nonblocking direct `send` on the connected socket, `seq+=1`); `on_reply_recv` (ssid check, D1 math, outlier discard, record); `on_export_tick` (snapshot → damping → fan `MetricUpdate` → `window.reset()`); `on_probe_recv` (allow-list per §2, `build_reply`, `reflect_tx`); `process_cm_msg` (drain; no own config in Phase 1), `process_show_msg`, `event_loop` (select rx / cm.rx / show.rx / client_req.rx), `serve()` |
| `show.rs` | `show_build()` registering `/show/stamp`, `/show/stamp/session`, `/show/stamp/statistics` via `Builder` (copy of `bfd/show.rs:30-39`); text + `json` (serde rows) renderers: summary (iface, local→remote, state Active/Idle by `last_rx` age vs 3×interval, sent/recv, loss %, last export), per-session detail, sender+reflector counters |
| `integration.rs` | `#[cfg(test)]` loopback test mirroring `bfd/integration.rs`: one `Stamp::new_with(127.0.0.1:0)`, subscribe `{local:127.0.0.1, remote:127.0.0.1, ifindex:0}` with `dst_port = instance reflector port`, `interval 50 ms`, `damping 1 s`; assert a `MetricUpdate` with `Some(snapshot)`, `min ≤ avg ≤ max`, within 10 s |

### Step 2 — Daemon wiring

1. `zebra-rs/src/main.rs`: add `mod stamp;` (alphabetical, after `srv6`... it sits with the
   other proto mods; place after `spf`/`srv6` like the existing list style).
2. New `zebra-rs/src/config/stamp.rs`: `spawn_stamp` / `despawn_stamp` — line-for-line mirror
   of `config/bfd.rs` (idempotent via `protocol_tasks["stamp"]`,
   `ProtoContext::default_table_no_rib()`, publish `stamp_client_tx`, non-fatal bind failure).
3. `zebra-rs/src/config/manager.rs`:
   - field `pub stamp_client_tx: RefCell<Option<UnboundedSender<crate::stamp::client::ClientReq>>>`
     next to `bfd_client_tx` (`:216`), init in `new` (`:270`).
   - `commit_config`: seed a `stamp` running-flag from `cm_clients` (like `bfd` at `:446`);
     in the `router ospf` (`:498`) and `router isis` (`:510`) arms call `spawn_stamp(self)`
     before `spawn_ospf`/`spawn_isis` (the `router ospfv3` arm does **not** spawn it — v3 has
     no measurement YANG; `spawn_ospfv3` still forwards whatever handle exists).
   - despawn block (after `:624`): drop `stamp` when neither `router ospf` (prefix also
     covers ospfv3 — conservative, harmless) nor `router isis` remains.
4. `zebra-rs/src/config/mod.rs`: `mod stamp;` + re-export beside the bfd ones (match whatever
   `config/mod.rs` does for `bfd`).

### Step 3 — YANG

1. `zebra-rs/yang/config.yang` — inside **both** te-metric containers
   (OSPF `:643-703`, IS-IS `:2158-2215`) add:

   ```yang
   container measurement {
     ext:help "Measure this link's delay dynamically (STAMP, RFC 8762)";
     description
       "Active performance measurement of this link. When enabled, a
        STAMP Session-Sender (RFC 8762, unauthenticated) probes the
        P2P neighbor once the adjacency is up; the damped min/max/avg
        delay and delay variation populate the same te-metric fields
        as static configuration (a static leaf, when set, overrides
        the measured value per field). The probes are answered by the
        neighbor's implicit Session-Reflector, so measurement must be
        enabled on both ends of the link.";
     leaf enable {
       type boolean;
       description "Activate measurement on this interface.";
     }
     leaf interval {
       type uint32 { range "100..60000"; }
       units "milliseconds";
       description "Probe transmit interval. Default 1000 ms.";
     }
     leaf damping-period {
       type uint32 { range "1..3600"; }
       units "seconds";
       description
         "Minimum spacing between exports to the IGP; each period's
          samples form the advertised min/max/avg window. Default 30 s.";
     }
   }
   ```

   (No YANG `default` statements — sibling leaves here use code-side defaults; keeps
   the config diff/display behavior consistent.)

2. `zebra-rs/yang/exec.yang` — after the `bfd` container (`:201-217`):

   ```yang
   container stamp {
     ext:help "STAMP (RFC 8762) link delay measurement";
     presence "Show STAMP session summary";
     leaf session {
       ext:help "Per-session detail";
       type empty;
     }
     leaf statistics {
       ext:help "Sender and reflector packet counters";
       type empty;
     }
   }
   ```

3. Pin with parse tests in `config/manager.rs` `yang_load_tests` (`:1263`, the
   `remove_private_as` test is the template): one config path per protocol
   (`set router isis interface eth0 te-metric measurement enable true`,
   `set router ospf area 0 interface eth0 te-metric measurement interval 100`) and the three
   show paths. (`configure_mode_loads` / `exec_mode_loads` already gate schema validity.)

### Step 4 — IS-IS integration

1. `isis/link.rs`:
   - `LinkConfig`: add `pub te_metric_measurement: MeasurementConfig` (after `te_metric`, `:308`).
   - `LinkState`: add `pub measured_te_metric: LinkTeMetric` and
     `pub stamp_session: Option<(stamp::session::SessionKey, stamp::session::SessionParams)>`
     (tracked subscription, OSPF-neighbor-style diff-gate).
   - `impl IsisLink { pub fn te_metric_effective(&self) -> LinkTeMetric }` — per-field
     `config.or(measured)` (D10) + unit test (config wins, measured fills gaps).
   - Config callbacks `config_te_measurement_{enable,interval,damping_period}` —
     parse ifname + value, store, then send the new `Message::StampReconcile(ifindex)`;
     on disable also clear `measured_te_metric` + `LspOriginate` both levels (mirror
     `config_te_metric`, `:1275-1288`).
2. `isis/config.rs` (`:364-383` block): register the three new callback paths
   `/router/isis/interface/te-metric/measurement/{enable,interval,damping-period}`.
3. `isis/inst.rs`:
   - `Isis` fields: `stamp_client_tx`, `stamp_event_tx`, `stamp_event_rx` (next to the bfd
     trio, `:414-429`); `Isis::new` gains `stamp_client_tx` param (after `bfd_client_tx`,
     `:606`) — update `config/isis.rs::spawn_isis` and `isis/vrf.rs` child construction
     (children pass `None`, D15).
   - `Message::StampReconcile(u32)` variant (+ `Display` arm near `:3029`).
   - `stamp_reconcile_link(&mut self, ifindex)` — compute desired
     `(SessionKey, SessionParams)`: measurement enabled ∧ `is_p2p` ∧ an Up adjacency on
     either level ∧ v4 pair (`link.state.v4addr.first()` × `nbr.addr4.keys().next()`,
     same selection as `bfd_reconcile_all`, `:1947-1976`); diff against
     `link.state.stamp_session`; Unsubscribe stale / Subscribe new with
     `notifier = stamp_event_tx`; store. `stamp_reconcile_all()` = loop over links.
   - `process_cm_msg` CommitEnd hook (`:751-763`): add `self.stamp_reconcile_all()` —
     one robust hook covers every config path that can flip a session (enable, interval,
     network-type, afi enable...).
   - `process_stamp_event(&mut self, ev)`: `MetricUpdate{key, snapshot}` → link by
     `key.ifindex`, verify tracked key, map snapshot →
     `LinkTeMetric { unidirectional_delay: avg, min_delay, max_delay, delay_variation: variation, loss: None }`
     (or `default()` on `None`), store in `state.measured_te_metric`, `LspOriginate` L1+L2.
   - `event_loop` (`:2324-2346`): add `stamp_event_rx` arm; `process_msg`: handle
     `StampReconcile`.
4. Runtime triggers:
   - `isis/packet.rs` — in `bfd_nfsm_dispatch`'s caller path (the Up-edge dispatch, `:85-103`):
     also send `Message::StampReconcile(link.ifindex)` on an NFSM transition to/from Up.
   - `isis/nfsm.rs::nbr_hold_timer_expire` (`:51-146`): send `StampReconcile(ifindex)` after
     teardown (the reconcile sees the removed neighbor and unsubscribes).
5. Origination merge:
   - `isis/lsp.rs` `:815-827` (TLV 22) and `:1005-1019` (TLV 222): build
     `let te_metric = link.te_metric_effective();` once and use it for both the ASLA build
     and the inline `sub_tlvs()` extend.
   - `isis/graph.rs` `:664` (flex-algo local-link min-delay):
     `.and_then(|link| link.te_metric_effective().min_delay)`.

### Step 5 — OSPFv2 integration (generic over `Ospf<V>`, active for v2)

1. `ospf/link.rs`:
   - `LinkConfig`: add `pub te_metric_measurement: MeasurementConfig` (after `:125`).
   - `OspfLink`: add `pub measured_te_metric: LinkTeMetric`,
     `pub stamp_session: Option<(SessionKey, SessionParams)>` (+ init in `OspfLink::from`).
   - `te_metric_effective()` + unit test (mirror IS-IS).
2. `ospf/config.rs`: register
   `/area/interface/te-metric/measurement/{enable,interval,damping-period}` (`ospf_add`
   block `:111-130`); callbacks parse area-id + ifname + value (template
   `config_ospf_interface_te_metric`, `:705-722`), store, call
   `ospf.stamp_reconcile_link(ifindex)`; disable also clears `measured_te_metric` +
   `ext_link_lsa_originate(ifindex)`. **v2 only** (no `config_v3.rs` registration).
3. `ospf/inst.rs`:
   - `Ospf<V>` fields: `stamp_client_tx`, `stamp_event_tx`, `stamp_event_rx` (next to bfd
     trio `:346-351`); both constructors (`Ospfv2::new` `:1015`, v3 `:5005`) gain the
     param — update `config/ospf.rs::spawn_ospf`/`spawn_ospfv3` and `ospf/vrf.rs`
     (children: `None`).
   - `stamp_reconcile_link(&mut self, ifindex)` (generic impl block near
     `bfd_reconcile_nbr` `:448`): desired iff measurement enabled ∧
     `network_type == PointToPoint` ∧ a Full neighbor ∧ `V::bfd_addrs` yields a pair
     (v3 returns `None` ⇒ inert); diff-gate against `link.stamp_session`;
     subscribe/unsubscribe; store.
   - `process_stamp_event`: store measured on link, `ext_link_lsa_originate(ifindex)`.
   - Trigger sites: after the existing `bfd_reconcile_nbr` calls in the NFSM arms
     (`:4725` v2, `:6849` v3) add `self.stamp_reconcile_link(index)`; in
     `nfsm_kill_neighbor` (`:3470` v2, `:8066` v3) after neighbor removal.
   - Event-loop arms in both loops (`:4933` v2, `:8641` v3).
4. Origination merge: `ext_link_lsa_originate` `:1984` →
   `link.te_metric_effective().asla_sub_subs()`. (Flex-algo SPF consumption needs no change:
   `flex_algo_link_delay` reads the LSDB, which now carries merged values from our own LSA.)

### Step 6 — Workspace tests

- Unit tests embedded per Step-1 file (timestamp, stats, damping, reflector, session table).
- `te_metric_effective` tests in both `isis/link.rs` (`te_metric_tests` `:2399`) and
  `ospf/link.rs` (`:745`) modules.
- Stamp loopback integration test (Step 1, `integration.rs`).
- YANG parse pins (Step 3.3).

### Step 7 — BDD

1. New step in `bdd/tests/cucumber.rs`:
   `show command {string} in namespace {string} should eventually contain {string}` —
   positive polling sibling of `show_command_eventually_not_contains` (`:917-955`),
   60 × 1 s, with the same diagnostics-on-failure.
2. Feature `bdd/tests/features/stamp_te_metric.feature`, tag `@stamp_te_metric`
   (verify no tag-prefix collision with `grep -rh "^@" bdd/tests/features/`), configs under
   `bdd/tests/configs/stamp_te_metric/{st1,st2}.yaml`:
   - Two namespaces `st1`/`st2`, one veth pair (feature-unique interface names
     `st1-st2`/`st2-st1`), addresses `192.168.61.0/30` range + loopbacks.
   - Both routers run **both** `router isis` (P2P, ipv4 enable) and `router ospf`
     (area 0, `network-type: point-to-point`, `segment-routing: mpls` — required for the
     Extended-Link LSA gate) with
     `te-metric: { measurement: { enable: true, interval: 100, damping-period: 2 } }`
     on the link interface — deliberately exercising the shared-session/multi-client path (D11).
   - Scenario 1 (bring-up): clean env, namespaces, veth, start, apply, wait, ping across.
   - Scenario 2 (IS-IS): `show isis database detail` **eventually contains**
     `"Min/Max Unidirectional Link Delay"` (renderer string verified at
     `crates/isis-packet/src/sub/neigh_disp.rs:84`); `show stamp` contains the remote addr.
   - Scenario 3 (OSPF): `show ospf database detail` eventually contains
     `"Min/Max Unidirectional Link Delay"` (`ospf/show.rs:1609`).
   - Scenario 4 (static override): not in Phase-1 BDD — covered by unit tests (keeps the
     feature fast).
   - Final scenario: **Teardown topology** — stop zebra-rs in each ns, delete each ns,
     `the test environment should be clean` (repo rule).
3. `bdd/Makefile`: `stamp_te_metric:` target; regenerate docs (`make docs` →
   `bdd/docs/stamp_te_metric.md`).

### Step 8 — Verification & delivery

1. `cargo build` + full `cargo test --workspace --exclude bdd` (CI parity), `cargo fmt`,
   `cargo clippy --workspace --all-targets -- -D warnings` (touch new files if cache-stale).
2. BDD run: `cargo build --release`, **md5 the binary, install to `/usr/bin/zebra-rs` +
   sync `zebra-rs/yang/ → /etc/zebra-rs/yang/`** (manual-install gotcha; other worktrees can
   stomp these — re-check md5 immediately before the run), then
   `cd bdd && make stamp_te_metric`. Also re-run one existing IS-IS + one OSPF feature
   (e.g. `make isis_l1p2p ospfv2_tilfa`) to catch origination regressions from the
   `te_metric_effective` refactor.
3. Update the parent plan doc's §3 status table (measurement runtime: Phase 1 done) in the
   same PR.
4. Single PR from `stamp-phase1` with commits ordered: core module → wiring/YANG → IS-IS →
   OSPF → tests/BDD/docs. PR description lists D1-D16 and the §2 deviation explicitly.

---

## 5. Risks / open questions

| Risk | Mitigation |
|------|------------|
| Port 862 already bound on a host (external TWAMP daemon) | Non-fatal spawn (warn + no task), like ND's raw-socket failure; sender-only operation still impossible Phase 1 (reflector socket is the instance gate) — acceptable, logged clearly. |
| LSP/LSA churn if damping thresholds mis-tuned | D7 constants + BDD uses damping 2 s only in the lab; defaults 30 s. Verification checklist row "LSP seq not changing on every probe" from the parent plan §11 checked manually during the BDD run. |
| `te_metric_effective()` refactor touches 6 origination/SPF sites | Existing static-te-metric unit tests (`isis/link.rs:2399`, `ospf/link.rs:745`) plus existing flex-algo BDDs re-run in Step 8.2. |
| Both-IGPs-one-link BDD is a new config shape | If flaky, fall back to two scenarios with separate veth pairs — decided at Step 7 execution time. |
| Shared-session params (D11) surprise (isis interval 100 vs ospf 200) | Last-writer-wins documented in `client.rs` + Subscribe handler; both IGPs in the BDD use identical params. |
| `rx_invalid` on clock step (NTP slew during probe) | D1 outlier discard; counted and visible in `show stamp statistics`. |

---

## 6. Explicitly deferred (tracked for Phase 2+)

- Configured reflector block (`services monitoring stamp`) + external-controller allow-list.
- LAN circuits; IPv6 sessions (incl. IS-IS v6-only adjacencies); VRF sessions (per-VRF 862).
- Loss export to the IGP; anomalous-flag raising on threshold crossing (`asla_sub_subs()`
  comments already anticipate the parameter).
- RFC 8972 TLVs beyond Extra-Padding; RFC 9503 return path / SR-MPLS encap (Phase 3).
- `stamp { tracing }` config + dedicated trace module (BFD-style) if debug volume warrants.
- Accuracy/offload ladder (see §7): sender `SO_TIMESTAMPING` (Phase 1.5), XDP reflector +
  sender-RX fastpath, HW timestamps
  ([offload notes §9b](./bfd-sbfd-stamp-xdp-offload-notes.md)).

---

## 7. XDP/eBPF offload readiness (analysis summary)

Full analysis: [bfd-sbfd-stamp-xdp-offload-notes.md §9b](./bfd-sbfd-stamp-xdp-offload-notes.md)
(2026-06-12). The conclusions that bind Phase 1:

**Why it matters here:** the D1 math cancels only the *measured* reflector residence; the four
userspace stamp-to-wire residues survive, halved:
`delay_est = wire/2 + (a+b+c+d)/2`. Min-delay (the Flex-Algo edge cost) self-filters via the
window minimum; **max-delay and delay-variation absorb daemon-scheduling tails** — honest on
ms-class WAN links, scheduling-dominated on µs-class fabric. Offload (and cheaper socket
timestamping) exists to shrink those residues; Phase 1 ships userspace anyway because the
primary delay-TE regime is ms-class and correctness/interop come first.

**Phase-1 structural requirements** (all already implied by §4 design, made binding here):

| R | Requirement | Why |
|---|-------------|-----|
| R1 | `reflector.rs::build_reply` stays a pure function with byte-level unit tests | It is the executable spec a future XDP program mirrors (in-place 44-octet rewrite — both base packets are `BASE_LEN`, reflector fields overwrite sender MBZ) |
| R2 | Reflector allow-list kept as plain per-session data `(local, remote)` | Becomes a BPF map keyed the same way; also the future in-kernel anti-abuse gate |
| R3 | T1 stamped at one build site; T4 captured at one read-task boundary | `SO_TIMESTAMPING` cmsg (rung 1/2) or kernel-map timestamps (rung 3) swap in at a single seam |
| R4 | All samples enter stats through `StatsWindow::record_delay` | A kernel-aggregate mode later feeds `{min,max,sum,count,jitter}` per export period beneath the same damping layer |
| R5 | Reflector counters tracked per session/source, not only globals | Substituted by helper map readouts when XDP consumes probes |
| R6 | `SessionKey` keeps `ifindex` | Per-ifindex helper acquire/release keys off it (BFD `EchoReflectors` model) |

**Two facts that shape the later offload work** (no Phase-1 action, recorded so they aren't
re-discovered): (1) only one XDP program attaches per interface and `xdp-bfd-echo` already
owns that hook wherever BFD Echo/detect runs — STAMP matching must join the *same* program
object, which makes promoting `Bfd`-private `EchoReflectors` into a shared offload supervisor
a prerequisite refactor; (2) the cheapest accuracy wins are not eBPF at all —
`SO_TIMESTAMPING` RX (then TX/errqueue) on the existing sockets — recommended as the first
post-Phase-1 follow-up.
