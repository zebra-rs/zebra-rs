# Lua Scripting Integration for zebra-rs — Loc-RIB Policy Hooks

Status: **design / proposal** (branch `lua`)
Prior art: FRR Scripting (合田和也, ENOG90 2026-06-19 — "FRR Scripting は何ができるのか").

This document designs an embedded-Lua scripting facility for zebra-rs, modelled
on FRR's `route-map match script` hook but **redesigned around the gaps that talk
surfaced**. The agreed first step (per Kunihiro) is two hooks on the **Adj-RIB-In →
Loc-RIB** boundary of BGP:

1. **import hook** — fires when a received path is admitted from Adj-RIB-In into
   the Loc-RIB (the inbound-policy decision point). The script sees the prefix,
   the full path attributes, and the sending peer, and may *observe*, *deny*, or
   *modify* attributes.
2. **withdraw hook** — fires when a path is removed from the Loc-RIB. A withdraw
   on the wire carries **only the NLRI**, so the hook reads the **stored Loc-RIB
   attributes of the path being removed** and hands them to the script. This is
   the half FRR structurally cannot do.

Egress / Adj-RIB-Out origination hooks and the route-map `match script` clause are
explicitly **later phases**, layered on the same engine.

**Decisions locked (2026-06-21):**
- The import hook includes **attribute write-back** in step 1 — `RM_MATCH_AND_CHANGE`
  is in scope from the start, not deferred. The script can mutate `med`,
  `local_pref`, `community`, `ext_community`, etc. and have the change land in the
  Loc-RIB.
- **IPv4-unicast first; EVPN Type-2 is Phase 2.** The policy engine is IPv4-typed
  today, so step 1 wires the v4 ingest/withdraw paths; EVPN marshalling
  (`prefix.evpn`) and the full GBP demo follow in Phase 2.

---

## 1. Why — what FRR proved, and what it could not do

FRR exposes Lua at two points only (`on_rib_process_dplane_results` in zebra, and
`route-map match script` in any daemon). The talk's worked example is **GBP
(Group-Based Policy) over EVPN**: a Group-Policy-ID (GPI) BGP Extended Community
(`draft-wlin-bess-group-policy-id-extended-community`, type `0x03` sub-type `0x17`,
carrying a 16-bit tag) is attached to EVPN Type-2 (MAC) routes; receivers extract
the tag and program nftables sets (`tag_100`, `tag_200`, …) to enforce
group-to-group accept/deny.

The talk hits three walls — all of which zebra-rs is positioned to avoid:

| # | FRR limitation | zebra-rs answer |
|---|----------------|-----------------|
| L1 | Stock FRR Lua exposes only `metric` / `ifindex` / `aspath` / `localpref`; **Extended-Communities are invisible** — the presenter had to patch `bgpd` to expose `attributes.ext_community`. | `BgpAttr` already carries `ecom: Option<ExtCommunity>` and `lcom` natively (`crates/bgp-packet/src/bgp_attr.rs`). We expose the **whole** attribute set from day one. |
| L2 | **No withdraw hook.** route-map is not invoked on withdraw, so nftables elements leak on EVPN withdraw. The `on_rib_process_dplane_results` hook *could* fire on delete, but it runs in **zebra** and has no access to **bgpd's** ext-comm → cannot recover the tag. | zebra-rs is a **single multi-threaded process**. The withdraw hook runs in the BGP module with the **removed Loc-RIB row's `attr` in hand** (`route_ipv4_withdraw` already returns `removed[].attr`). The tag is right there. |
| L3 | Cross-daemon "cookie" problem — FRR wants a way to carry the MAC↔TAG binding across the bgpd/zebra boundary. | No boundary. Loc-RIB *is* the shared state; the withdraw hook reads it directly. |

So the first step is deliberately the two Loc-RIB hooks: they (a) give Lua the full
attribute set including ext-communities, and (b) make teardown-on-withdraw a
first-class, in-process operation.

---

## 2. Scope

**In scope (Phase 1–4):**
- An embedded Lua 5.4 runtime behind a Cargo feature `lua`. (Originally off by
  default — mirroring FRR's `--enable-scripting` — but now **on by default**; build
  without it via `--no-default-features`, where the hooks compile to no-ops.)
- Import hook on `route_ipv4_update` (and the v4 batch/shard reduce paths).
- Withdraw hook on `route_ipv4_withdraw` (and the shard `WithdrawV4` reduce).
- A read/write marshalling layer for `prefix`, `attributes` (incl. `ext_community`),
  and `peer`.
- A safe host-helper surface (logging, a key/value map service, a fire-and-forget
  side-effect channel for nftables/exec — *not* inline blocking I/O).
- Config + YANG to bind a named script to the import/withdraw hooks, per-AFI.

**Out of scope for step 1 (later phases, §11):**
- EVPN Type-2 import/withdraw hooks (same mechanism, EVPN marshalling).
- Egress / Adj-RIB-Out origination hook (the GBP *advertise* side that *adds* the GPI ecom).
- route-map `match script` / `set script` clause (FRR parity, per-sequence).
- IPv6/VPN families (the policy engine is IPv4-typed today; v6 follows the same shape).

**Non-goals:** replacing the native route-map; a general plugin/FFI system; running
untrusted scripts (scripts run with daemon privileges — operator-trusted, like FRR).

---

## 3. Architecture

### 3.1 Crate / module layout

```
zebra-rs/src/script/            <- new module, behind feature = "lua"
  mod.rs            ScriptEngine, ScriptRegistry, generation counter
  marshal.rs        BgpAttr/Peer/prefix  <->  Lua tables & UserData
  ecom.rs           ExtCommunity <-> Lua (raw 8-byte list + typed gpi() helper)
  host.rs           sandboxed host API: zlog, map, sideeffect
  hooks.rs          loc_rib_import() / loc_rib_withdraw() entry points
```

The BGP module calls `script::hooks::loc_rib_import(...)` / `loc_rib_withdraw(...)`.
When the feature is off, these are `#[inline] fn …() {}` no-ops, so the ingest path
compiles unchanged and pays nothing.

### 3.2 Runtime choice: `mlua`

- `mlua` with features `lua54`, `vendored` (bundles the interpreter — no system
  dep), and `serde` (table ⇄ Rust via `serde`).
- Rationale: actively maintained, Lua 5.4 (the version FRR moved to), `UserData`
  for zero-copy mutable wrappers, `vendored` keeps CI hermetic. `rlua` is now a thin
  shim over `mlua`.

### 3.3 Threading model — the hard part FRR doesn't have

zebra-rs runs BGP ingest across an async runtime and, at `N>1`, a **sharded
lock-free Loc-RIB** (v4-unicast lives on the shard pool, not `main`; see
`docs/design/` RIB-sharding notes and the `ShardMsg::WithdrawV4` reduce in
`route_ipv4_withdraw`). An `mlua::Lua` is `!Sync` and cannot be shared mutably
across threads. `policy_list_apply_net` is a **synchronous** function returning
`Option<PolicyDecision>`, called from both the async peer task and the shard
reduce — so the hook must be callable synchronously from whatever thread owns the
route.

**Decision: thread-local VM + global script registry + generation counter.**

```
ScriptRegistry (global, Arc<ArcSwap<Scripts>>):   compiled-source + generation:u64
thread_local! ENGINE: RefCell<Engine>             one mlua::Lua per worker thread
```

- On the hot path, the hook borrows the thread-local `Engine`. If
  `Engine.generation != registry.generation`, it recompiles the scripts into *this
  thread's* VM (cheap, lazy, once per thread per reload) and bumps its local gen.
- No cross-thread VM sharing, no global lock on the hot path. Each shard worker and
  each peer task gets its own VM. Pure match/transform is embarrassingly parallel —
  exactly how `route_ipv4_update_batch` already fans the policy walk across cores
  with rayon.
- Script *state* is therefore **per-thread** and must not be relied on for
  cross-route memory. Shared state lives in Rust (the host `map` service, §3.5),
  not in Lua globals.

### 3.4 Pure vs side-effecting — no inline blocking I/O

FRR's GBP scripts call `http.request(...)` and `os.execute("nft …")`
**synchronously inside the route path**. FRR tolerates the stall because bgpd is
single-threaded per peer. In zebra-rs that would block an async worker or a shard
reduce — unacceptable.

Two tiers:

- **Pure tier (default):** the script may read/modify `prefix`/`attributes`/`peer`
  and call non-blocking host helpers (`zlog`, `map.get`). Runs **inline** on the
  thread-local VM. Deterministic, bounded.
- **Side-effect tier (opt-in):** anything external (program nftables, HTTP) is
  expressed as a **message**, not a blocking call. The script calls
  `sideeffect.nft{op="add", set="tag_100", elem=mac}` which enqueues onto an
  `mpsc` drained by a dedicated `tokio` task (or `spawn_blocking` for `nft`/exec).
  The route path never blocks; ordering per (set) is preserved by the single
  drainer. The MAC→tag lookup that FRR did over HTTP becomes `map.get("sgt", mac)`
  against an in-memory table that a background task refreshes — a synchronous map
  read on the hot path, async refresh off it.

This is strictly better than FRR's model and leans on zebra-rs being one process
with shared memory + an async runtime.

### 3.5 The host `map` service

A small `Arc<RwLock<HashMap<String, HashMap<String,String>>>>` (namespace → key →
value), seeded from config and/or refreshed by a background fetcher task. Exposed to
Lua as `map.get(ns, key)`. This replaces FRR's blocking `http.request` with a
non-blocking lookup, while a Rust task does the HTTP refresh out of band.

---

## 4. The Lua contract

### 4.1 Entry points

Mirror FRR's `route_match` shape so scripts stay familiar/portable. Two functions,
selected by hook:

```lua
-- import: Adj-RIB-In -> Loc-RIB. May observe / deny / modify.
-- Returns an action; on MATCH_AND_CHANGE the (mutated) attributes are read back.
function loc_rib_import(prefix, attributes, peer,
                        RM_FAILURE, RM_NOMATCH, RM_MATCH, RM_MATCH_AND_CHANGE)
    ...
    return { action = RM_MATCH_AND_CHANGE, attributes = attributes }
    -- or { action = RM_NOMATCH }  (admit unchanged; convention: "no opinion")
    -- or { action = RM_FAILURE }  (deny — drop before Loc-RIB)
end

-- withdraw: path leaving the Loc-RIB. attributes are the STORED Loc-RIB attrs
-- of the path being removed (read-only). Return value is ignored for routing;
-- the hook is for side-effects (teardown). action=RM_FAILURE is logged only.
function loc_rib_withdraw(prefix, attributes, peer,
                          RM_FAILURE, RM_NOMATCH, RM_MATCH, RM_MATCH_AND_CHANGE)
    ...
    return { action = RM_NOMATCH }
end
```

Action semantics for the **import** hook (maps onto the existing
`Option<PolicyDecision>` contract of `policy_list_apply_net`):

| Lua `action` | Effect on import |
|---|---|
| `RM_FAILURE` | Deny — route is dropped (returns `None`, like a route-map `deny`). |
| `RM_NOMATCH` | Admit the route **unchanged** (script had no opinion). |
| `RM_MATCH` | Admit unchanged (explicit match, no attr edits). |
| `RM_MATCH_AND_CHANGE` | Admit with the script's mutated `attributes`. |

Errors / a missing function / a non-table return are **fail-safe**: logged, treated
as `RM_NOMATCH` (admit unchanged) so a broken script never silently blackholes
traffic. (Configurable to `RM_FAILURE`=deny for fail-closed deployments.)

### 4.2 `prefix`

```lua
prefix.network   -- "10.0.0.0/24"  (string, FRR-compatible)
prefix.afi       -- "ipv4" | "ipv6" | "evpn"
prefix.addr      -- "10.0.0.0"
prefix.len       -- 24
-- EVPN (phase 2):  prefix.evpn = { route_type=2, mac="aa:bb:cc:dd:ee:00",
--                                  ip=..., vni=..., rd=... }
```

For EVPN, zebra-rs parses the route natively, so the script gets a **structured**
`prefix.evpn.mac` instead of FRR's brittle `tostring(prefix.network):match(...)`
regex on `[2]:[0]:[48]:[aa:bb:cc:dd:ee:00]`.

### 4.3 `attributes` — the full set (fixes L1)

Exposed as `UserData` so reads are lazy and writes mutate a working `BgpAttr` the
host reads back. Field map (R = readable, W = writable in import hook):

| Lua field | `BgpAttr` source | R | W |
|---|---|---|---|
| `attributes.med` | `med: Option<Med>` | ✓ | ✓ |
| `attributes.local_pref` | `local_pref: Option<LocalPref>` | ✓ | ✓ |
| `attributes.weight` | local weight (PolicyDecision) | ✓ | ✓ |
| `attributes.origin` | `origin: Option<Origin>` ("igp"/"egp"/"incomplete") | ✓ | ✓ |
| `attributes.as_path` | `aspath: Option<As4Path>` (list of ASNs) | ✓ | ✓ |
| `attributes.next_hop` | `nexthop: Option<BgpNexthop>` | ✓ | ✓ |
| `attributes.community` | `com: Option<Community>` (list "ASN:val") | ✓ | ✓ |
| `attributes.large_community` | `lcom: Option<LargeCommunity>` | ✓ | ✓ |
| `attributes.ext_community` | `ecom: Option<ExtCommunity>` (list of 8-byte values) | ✓ | ✓ |

`ext_community` is the headline. It is a list of opaque 8-octet values so the
FRR-style `string.pack(">BBHHH", …)` / `string.unpack` idiom works **verbatim**,
plus a typed convenience (§4.5).

### 4.4 `peer`

Read-only, populated from `Peer`:

```lua
peer.remote_as, peer.local_as,
peer.remote_id, peer.local_id,            -- router-ids
peer.remote_address, peer.local_address,
peer.state,                               -- "Established" etc.
peer.is_ibgp,
peer.description
-- stats/timers can be added incrementally (FRR exposes a large table; we add on demand)
```

### 4.5 Host helpers (sandboxed)

The base sandbox **removes** `os`, `io`, `package`, `require`, `dofile`,
`loadfile`. In their place:

```lua
zlog.info(msg) / zlog.warn(msg) / zlog.error(msg)   -- into the daemon log
map.get(ns, key)            -- non-blocking lookup (e.g. map.get("sgt", mac))
ecom.gpi(tag)               -- build a GPI ext-community value (type 0x03, sub 0x17)
ecom.parse_gpi(value)       -- -> tag or nil   (typed decode; avoids manual unpack)
sideeffect.nft{op=, table=, set=, elem=}            -- enqueue nft mutation (tier 2)
```

`string.pack`/`string.unpack`/`string`/`table`/`math` remain available (pure).

---

## 5. Marshalling (Rust ⇄ Lua)

- `prefix` and `peer`: built as plain Lua tables once per hook call (small, cheap).
- `attributes`: an `mlua::UserData` wrapper around `&mut BgpAttr` (+ working weight)
  with `__index`/`__newindex` metamethods. Reads pull from the live `BgpAttr`;
  writes set an "dirty" flag and the field. After the call, if `action ==
  MATCH_AND_CHANGE`, the host keeps the mutated `BgpAttr`; otherwise it discards it.
- `ExtCommunity` ⇄ Lua: `marshal::ecom` converts to/from a Lua sequence of 8-byte
  binary strings (matching FRR). `ecom.gpi`/`ecom.parse_gpi` are Rust closures that
  encode/decode the GPI layout so scripts don't hand-roll byte math.
- Lifetime: the `UserData` borrows for the duration of the synchronous call only;
  nothing escapes the VM (we never store Lua refs to Rust data across calls).

---

## 6. Config & YANG

A defined-set holding script source/path, plus per-AFI binding of the two hooks.
New YANG `zebra-lua-policy.yang` augmenting the routing-policy tree:

```
policy
  lua-script <NAME>
    source-path <FILE>        # or inline `source <heredoc>` for tests
    fail-action permit|deny   # default permit (fail-safe)
bgp <ASN>
  loc-rib-hook ipv4-unicast
    import  <NAME>            # bind script NAME's loc_rib_import
    withdraw <NAME>           # bind script NAME's loc_rib_withdraw
```

Config example:

```
policy lua-script GBP
  source-path /etc/zebra-rs/lua/gbp.lua
bgp 65000
  loc-rib-hook ipv4-unicast import GBP withdraw GBP
```

Parsing follows the existing `PolicyConfig::exec()` dispatch; the binding lands in
new `Bgp`/per-AFI fields, and a `ScriptRegistry` reload bumps the generation counter
so thread-local VMs lazily recompile (§3.3). EVPN binds under
`loc-rib-hook l2vpn-evpn` in phase 2.

---

## 7. Integration points — step by step

### 7.1 Import hook (Adj-RIB-In → Loc-RIB)

`route_ipv4_update` (`zebra-rs/src/bgp/route.rs:2965`) today:

```rust
let decision = {
    let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
    route_apply_policy_in(peer, afi_safi, nlri, attr.clone(), 0)   // :2996
};
```

Insert the hook **after** native inbound policy, before
`route_ipv4_update_decided` writes the Loc-RIB:

```rust
let decision = route_apply_policy_in(peer, afi_safi, nlri, attr.clone(), 0);
#[cfg(feature = "lua")]
let decision = script::hooks::loc_rib_import(   // no-op when feature off
    bgp.script.as_ref(),                        // bound script for this AFI, or None
    IpNet::V4(nlri.prefix),
    decision,                                   // Option<PolicyDecision> threads through
    peer,
);
```

`loc_rib_import` is a thin wrapper: if no script is bound, or `decision` is already
`None` (native policy denied), return as-is; else build `prefix`/`attributes`(from
`decision.attr`)/`peer`, run `loc_rib_import`, and fold the action back into
`Option<PolicyDecision>`. The same call is added to the batch path
(`route_ipv4_update_batch`, :3058) and the shard ingest reduce so `N>1` is covered.

### 7.2 Withdraw hook (→ Loc-RIB removal) — reads stored attrs

`route_ipv4_withdraw` (`zebra-rs/src/bgp/route.rs:5466`) removes from Loc-RIB and
**returns the removed rows with their attributes**:

```rust
let mut removed = bgp.shard.remove(rd, nlri.prefix, nlri.id, ident);   // :5508
```

`removed[].attr` is the stored Loc-RIB attribute set of the path that just left —
already used downstream at :5585 (`gone.attr`). Fire the hook here:

```rust
let mut removed = bgp.shard.remove(rd, nlri.prefix, nlri.id, ident);
#[cfg(feature = "lua")]
if let Some(gone) = removed.first() {
    script::hooks::loc_rib_withdraw(
        bgp.script.as_ref(),
        IpNet::V4(nlri.prefix),
        &gone.attr,                 // <-- the attrs a wire-withdraw doesn't carry
        peers.get_by_idx(ident),
    );
}
```

**Sharding caveat (N>1):** v4-unicast withdraws are dispatched as
`ShardMsg::WithdrawV4` and reduced in `route_apply_bestpath_v4_batch`. The hook must
fire where `removed`/`gone.attr` is actually known — i.e. in the **shard reduce**,
not before dispatch. Phase 1 wires both the synchronous (VPNv4 / `N==1`) site shown
above **and** the reduce site; a unit test asserts the hook fires exactly once per
withdrawn path in both modes. (This mirrors the show/originate read-path lesson:
at `N>1` the v4 RIB is on the pool, so RIB-touching logic must run on the shard.)

### 7.3 Engine entry (`script/hooks.rs`, sketch)

```rust
pub fn loc_rib_import(
    script: Option<&BoundScript>, prefix: IpNet,
    decision: Option<PolicyDecision>, peer: &Peer,
) -> Option<PolicyDecision> {
    let (Some(script), Some(mut d)) = (script, decision) else { return decision; };
    ENGINE.with(|e| {
        let mut e = e.borrow_mut();
        e.sync(&SCRIPTS.load());                  // lazy recompile if generation changed
        match e.run_import(script, prefix, &mut d, peer) {
            Ok(Action::Failure)        => None,                  // deny
            Ok(Action::Change)         => Some(d),               // d.attr mutated in place
            Ok(_) /* NoMatch|Match */  => Some(d),               // admit unchanged
            Err(err) => { zlog_warn!(err); Some(d) }             // fail-safe: admit
        }
    })
}
```

---

## 8. Worked example — GBP over EVPN (receiver + teardown)

The two Phase-1 hooks implement the **consumer** half of the talk's demo (the
*advertise* half is the egress hook, Phase 5). With EVPN marshalling (phase 2) the
same hooks run for Type-2 routes. Single script, both functions:

```lua
-- /etc/zebra-rs/lua/gbp.lua

local function mac_of(prefix)
    return prefix.evpn and prefix.evpn.mac            -- native EVPN parse (no regex)
end

-- Receive: extract GPI tag from ext-community, program nftables.
function loc_rib_import(prefix, attributes, peer, FAIL, NOMATCH, MATCH, CHANGE)
    local mac = mac_of(prefix)
    if not mac then return { action = NOMATCH } end
    for _, ec in ipairs(attributes.ext_community) do
        local tag = ecom.parse_gpi(ec)                -- typed decode of 0x03/0x17
        if tag then
            sideeffect.nft{ op="add", table="bridge gbp_filter",
                            set="tag_" .. tag, elem=mac }  -- non-blocking enqueue
            zlog.info("gbp: " .. mac .. " -> tag " .. tag)
            break
        end
    end
    return { action = NOMATCH }                       -- observe only; route unchanged
end

-- Withdraw: the path is leaving the Loc-RIB. `attributes` are the STORED attrs,
-- so we still see the GPI tag and can remove the nft element. FRR cannot do this.
function loc_rib_withdraw(prefix, attributes, peer, FAIL, NOMATCH, MATCH, CHANGE)
    local mac = mac_of(prefix)
    if not mac then return { action = NOMATCH } end
    for _, ec in ipairs(attributes.ext_community) do
        local tag = ecom.parse_gpi(ec)
        if tag then
            sideeffect.nft{ op="delete", table="bridge gbp_filter",
                            set="tag_" .. tag, elem=mac }
            zlog.info("gbp: withdraw " .. mac .. " from tag " .. tag)
            break
        end
    end
    return { action = NOMATCH }
end
```

The MAC→tag map server (FRR's blocking HTTP GET) is only needed on the *advertise*
side (Phase 5); there it becomes `map.get("sgt", mac)` with a background refresher.

---

## 9. Phased PR plan (small PRs, branch `lua`)

| PR | Title | Content | Test | Status |
|----|-------|---------|------|--------|
| 1 | engine skeleton | `mlua` dep behind `lua` feature; thread-local VM + registry generation; `Action`/RM_* contract; sandbox (`os`/`io`/`package` stripped, per-script `_ENV`); no-op hooks when feature off. | unit: load source, call `loc_rib_import` → NOMATCH; sandbox + fail-safe. | **done** |
| 2 | marshalling / data model | `prefix` / read-only `attributes` (incl. `ext_community` as 8-byte values) / `peer` (`PeerView`) tables; `loc_rib_import(name, prefix, attr, peer) -> Action`. | unit: GPI `ext_community` `string.unpack`; prefix/peer marshalling; fail-safe. | **done** |
| 3 | config surface + ingest wiring | `zebra-bgp-lua.yang` augment (`lua-script source-path`, `loc-rib-hook ipv4-unicast import`); BGP config handlers → registry (`set_source` / `set_import_binding_v4`); hook at the shard chokepoint `handle_update_v4` (covers N=1 **and** N>1, plain v4-unicast; VPNv4 skipped). | unit: binding dispatch (Failure→deny); `configure_mode_loads` YANG test. | **done** |
| 4 | attribute write-back | `ImportOutcome { action, attr }`; read the script-mutated `attributes` table back onto the original `BgpAttr` on `MATCH_AND_CHANGE` (writable: `med`/`local_pref`/`origin`/`community`/`ext_community`; other attrs preserved); shard hook applies it; `ecom.gpi`/`parse_gpi` host helpers; `community`/`ext_community` always-present lists for append. | unit: set med/local-pref, append GPI ecom, clear-on-nil, NOMATCH-no-change. | **done** |
| 5 | withdraw hook + `zlog` | `loc_rib_withdraw` at `route_ipv4_withdraw` (synchronous N=1 / VPNv4 path), reading the **removed Loc-RIB row's stored `attr`**; observe-only; `loc-rib-hook ipv4-unicast withdraw` binding; full `lua_peer_view`; `zlog` host helper. N>1 `WithdrawV4` shard-reduce wiring + `map.get`/`sideeffect.nft` drainer = follow-up (PR5b). | unit: withdraw sees stored ext-community; missing-fn no-op; binding smoke. | **done** |
| 5b | side-effect channel | `sideeffect.nft{op,table,set,elem}` host helper → unbounded channel → background drainer task running `nft` off the hot path; spawned at daemon start. | unit: hook enqueues an `NftOp`; `nft_args` argv shape. | **done** |
| 5c | N>1 withdraw wiring | fire the withdraw hook on the sharded path too: the `WithdrawV4` handler removes the Loc-RIB row itself (reading `gone.attr`/`gone.router_id`/`gone.typ`) and hands it to `best_path_delta_v4` — covering N>1 (the default N=1 was PR5). | unit: `WithdrawV4` removes the row + reports it as `replaced`. | **done** |
| 5d | `map.get` lookup | non-blocking `map.get(ns, key)` (config-seeded / background-refreshed table) — the non-blocking replacement for FRR's blocking HTTP GET on the origination side. | unit: seed + read. | |
| 6 | GBP EVPN BDD | EVPN Type-2 marshalling (`prefix.evpn`); enrich the shard import peer table (remote-as/addresses); end-to-end `@bgp_lua_gbp` feature. Requires a **`--features lua` BDD binary** (see note). | BDD with explicit `Teardown topology`. | |

Each PR is independently revertible. **BDD note:** the BDD harness runs a
manually-installed `/usr/bin/zebra-rs`; the `lua` feature is **now on by default**, so a
stock release binary already includes the engine and the `@bgp_lua_gbp` BDD no longer
needs a special `--features lua` build. (Historically the lane needed that build.) Until
that lane
exists, Lua behaviour is covered by the `#[cfg(feature = "lua")]` unit tests.
Later: egress/origination hook (Phase 5b — *adds* the GPI ecom on advertise;
**must join `UpdateGroupSig`**, see §10), route-map `match script` clause (FRR
parity), IPv6/VPN. The shard peer table is partial today (router-id + IBGP/EBGP);
enriching it needs extra fields on `ShardUpdateV4` (PR6).

---

## 10. Risks & gotchas

- **`UpdateGroupSig` (for the later egress hook).** Any Lua transform on the
  *outbound* path changes per-neighbor egress attributes. Two peers with different
  bound scripts (or a different script generation) must **not** share an
  update-group. The bound-script identity + generation must be folded into
  `UpdateGroupSig`, or egress members silently leak each other's attrs. BDD won't
  catch this; the signature unit test will. (Not a Phase-1 concern — import/withdraw
  hooks are ingress — but called out so the egress phase doesn't repeat the
  as-override / outbound-knob trap.)
- **Sharding (N>1).** Both hooks must fire on the thread that owns the route (shard
  reduce), not before dispatch, or the withdraw hook sees no `removed.attr`. Tested
  explicitly in PR4.
- **No inline blocking I/O.** Enforced by the sandbox (no `os`/`io`) + the
  side-effect channel. A script that busy-loops still stalls its worker — Phase 1
  is pure/bounded; if scripts grow, add an instruction-count hook
  (`Lua::set_hook`) to cap runtime.
- **Fail-safe default.** Script error / missing function / bad return ⇒ log +
  `RM_NOMATCH` (admit unchanged). `fail-action deny` opt-in for fail-closed sites.
- **Hot reload races.** Generation counter + lazy per-thread recompile; a reload
  mid-batch is fine — each route uses whatever generation its thread last synced,
  and the next route picks up the new one. No partial-script visibility (compile is
  all-or-nothing into the VM).
- **Privilege.** Scripts run as the daemon. Gate behind the `lua` build feature
  *and* explicit config; document that `loc-rib-hook` grants code execution.
- **Determinism / ordering.** `sideeffect.nft` ops are serialized per-set by the
  single drainer, so add-before-delete ordering across an import→withdraw of the
  same MAC is preserved.

---

## 11. Later phases (sketch)

- **EVPN hooks (Phase 2):** same engine; `route_*_evpn` ingest/withdraw
  (`route_apply_policy_in_evpn` :2723, `route_withdraw_evpn` :4756) + `prefix.evpn`
  marshalling. Unlocks the full GBP demo.
- **Egress / origination hook (Phase 5b):** a hook on the Adj-RIB-Out build path
  that lets a script *add* attributes (the GBP advertise side: `map.get` the tag,
  `ecom.gpi(tag)`, append). **Joins `UpdateGroupSig`** (§10).
- **route-map `match script` / `set script` (Phase 6):** FRR-parity per-sequence
  clause. Reuses §4–5 wholesale; adds `PolicyEntry.match_script: Option<String>`
  and a call in `entry_matches` (`route.rs:11059`) + the `Permit|Next` set block
  (`route.rs:11000`). This is the closest analogue to FRR's actual hook, layered on
  top of the Loc-RIB hooks rather than instead of them.
- **IPv6 / VPN families:** once the policy engine is family-generic on the v6 side.

---

## 12. Summary

The first step — **import and withdraw hooks on the Adj-RIB-In → Loc-RIB
boundary** — is the highest-leverage slice: it hands Lua the full native attribute
set (including ext-communities, fixing FRR's L1), and makes **withdraw-time teardown
a first-class operation reading the stored Loc-RIB attrs** (fixing L2/L3, which
FRR's cross-daemon architecture cannot). Everything else (egress origination,
route-map `match script`, EVPN/v6) layers on the same engine and marshalling.
