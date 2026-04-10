# Plan: Extend `LocalRibTable` / `AdjRibTable` to hold EVPN RIB (Type 2 & 3)

Status: **draft / not yet implemented**
Scope: BGP EVPN (RFC 7432) Route Type 2 (MAC/IP Advertisement) and Type 3 (Inclusive Multicast Ethernet Tag) — RIB layer and `show ip bgp evpn` only.

---

## 1. Current state — what already exists

We do not need to build the wire-format parser. The exploration confirmed:

- **`bgp-packet` already parses EVPN Type 2 and Type 3.** `EvpnRoute::Mac(EvpnMac)` and `EvpnRoute::Multicast(EvpnMulticast)` live in `crates/bgp-packet/src/attrs/nlri_evpn.rs`. Both carry the `RouteDistinguisher` as a field.
- **MP_REACH / MP_UNREACH dispatch arms for `(L2vpn, Evpn)` already exist** at `crates/bgp-packet/src/attrs/mp_reach.rs:117` and `crates/bgp-packet/src/attrs/mp_unreach.rs:98`. They produce:
  - `MpReachAttr::Evpn { snpa, nhop, updates: Vec<EvpnRoute> }`
  - `MpUnreachAttr::Evpn(Vec<EvpnRoute>)` and `MpUnreachAttr::EvpnEor`
- **`Afi::L2vpn = 25` / `Safi::Evpn = 70`** are already defined in `crates/bgp-packet/src/afi.rs`.
- **An empty `show_bgp_l2vpn_evpn()` stub** exists at `zebra-rs/src/bgp/show.rs:1639`.
- A stray `println!("EVPN: {:?}", updates);` debug log exists at `crates/bgp-packet/src/attrs/mp_reach.rs:137` and should be removed as part of this work.

The gap is entirely in the **zebra-rs RIB layer** (`zebra-rs/src/bgp/route.rs` + `zebra-rs/src/bgp/adj_rib.rs`):

- `LocalRibTable` is hard-coded to `PrefixMap<Ipv4Net, Vec<BgpRib>>`.
- `AdjRibTable<D>` is hard-coded to `BTreeMap<Ipv4Net, Vec<BgpRib>>`.
- The `route_update()` dispatch in `route.rs:878` matches only `MpReachAttr::Vpnv4` and `MpReachAttr::Rtcv4`; EVPN MpReach/MpUnreach falls through to `_` and is silently dropped.

---

## 2. Design decisions

### D1. Dedicated EVPN key type — new enum, do not reuse `EvpnRoute`

EVPN keys are heterogeneous (different fields per route type). We will define a dedicated key type:

```rust
// Pseudo-code — illustrative only.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EvpnPrefix {
    /// Type 2: [2]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]
    MacIp {
        eth_tag: u32,
        mac: [u8; 6],
        ip: Option<IpAddr>,
    },
    /// Type 3: [3]:[EthTag]:[IPlen]:[OrigIP]
    InclusiveMulticast {
        eth_tag: u32,
        orig: IpAddr,
    },
    // Future: EthernetAd (Type 1), EthernetSegment (Type 4), IpPrefix (Type 5)
}

impl EvpnPrefix {
    pub fn route_type(&self) -> u8 { /* 2 or 3 */ }
    pub fn from_route(r: &EvpnRoute) -> (RouteDistinguisher, EvpnPrefix) { /* split */ }
}

impl Display for EvpnPrefix {
    // Type 2: "[2]:[<ethtag>]:[48]:[xx:xx:xx:xx:xx:xx]"  (no IP)
    //         "[2]:[<ethtag>]:[48]:[xx:..]:[<iplen>]:[<ip>]"  (with IP)
    // Type 3: "[3]:[<ethtag>]:[<iplen>]:[<orig>]"
}
```

**Rationale:** the key must derive `Ord`/`Eq`/`Hash` cleanly so it can index a `BTreeMap`, and it must format exactly as the user-supplied show output specifies. `EvpnRoute` itself bundles the RD with the key fields, which would awkwardly duplicate the RD in both the outer map and the inner key. Splitting into `(RD, EvpnPrefix)` is cleaner and matches the precedent `BTreeMap<RouteDistinguisher, LocalRibTable>` already used for VPNv4 (the inner table is keyed only on the prefix, not on the RD).

### D2. Parallel new table types instead of a generic refactor

Today `LocalRibTable` is `PrefixMap<Ipv4Net, Vec<BgpRib>>` plus a selected map. EVPN keys are exact-match (no longest-prefix), so `prefix-trie` is the wrong storage. Two options were considered:

| Option | Description | Cost |
|---|---|---|
| A | Generalize `LocalRibTable<K, M>` over key type and map type | Touches every existing call site (~30+ in `route.rs`); high risk of regression on the v4/vpnv4 paths |
| B | Add parallel `LocalRibEvpnTable` / `AdjRibEvpnTable<D>` structs that mirror the existing API but use `BTreeMap<EvpnPrefix, ...>` | Zero churn in existing IPv4/VPNv4 code paths; easy to revisit later |

**Choice: B.** Same precedent as VPNv4 (first-level `BTreeMap` rather than being squeezed into the v4 type). A unified generic refactor can come later if it pays off.

### D3. Hierarchical storage by RD (mirrors VPNv4)

```rust
// In LocalRib (zebra-rs/src/bgp/route.rs:355)
pub evpn: BTreeMap<RouteDistinguisher, LocalRibEvpnTable>,

// In AdjRib<D> (zebra-rs/src/bgp/adj_rib.rs:92)
pub evpn: BTreeMap<RouteDistinguisher, AdjRibEvpnTable<D>>,
```

EVPN routes are RD-scoped just like VPNv4, so iteration order (RD → routes within RD) matches the desired show output ("Route Distinguisher: 10.0.0.5:2" header followed by routes within that RD).

### D4. `BgpRib` value type unchanged

`BgpRib` carries the `Arc<BgpAttr>` and per-route metadata (path-id, peer, flags, etc.). It is NLRI-agnostic — the key in the surrounding map identifies the prefix. EVPN reuses it as-is. **No change to `BgpRib`.**

### D5. Best-path selection — minimal first cut

EVPN best-path has type-specific tiebreaks (e.g., MAC mobility sequence number for Type 2, DF election for Type 4). For this initial slice we use the same generic best-path comparator the IPv4 RIB uses (LocalPref / AS-Path / Origin / MED / Router-ID). This is good enough to compile, install, and display routes. **MAC mobility / DF election are explicitly out of scope for this plan.**

---

## 3. Step-by-step implementation plan

### Step 1 — `bgp-packet` additions

**Status:** Implemented in commit `db2d0ce`.

**File:** `crates/bgp-packet/src/attrs/nlri_evpn.rs`

1. Add `EvpnPrefix` enum (D1) with `MacIp` and `InclusiveMulticast` variants. Derive `Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash`.
2. Implement `Display for EvpnPrefix` matching the user-specified format:
   - Type 2 without IP: `[2]:[<ethtag>]:[48]:[mac]`
   - Type 2 with IP: `[2]:[<ethtag>]:[48]:[mac]:[<iplen>]:[<ip>]`
   - Type 3: `[3]:[<ethtag>]:[<iplen>]:[<orig>]`
   - MAC formatted as lowercase hex with colons: `fe:b2:14:6c:11:6c`.
3. Implement `EvpnPrefix::from_route(&EvpnRoute) -> (RouteDistinguisher, EvpnPrefix)`.
4. **Cleanup:** remove the stray `println!` at `crates/bgp-packet/src/attrs/mp_reach.rs:137`.

### Step 2 — New RIB table types and wiring

**Status:** Implemented in commit `67ea95e`. Steps 2 and 3 of the original plan
were bundled because the table type definitions and the `LocalRib`/`AdjRib`
field additions are inseparable in Rust — defining `LocalRibEvpnTable` without
a use site triggers dead-code warnings, and adding `LocalRib.evpn` requires
the type to exist. Step 3 below is preserved as a placeholder so existing
commit-message references to "Step 4 / 5 / 6 / 7" remain accurate.

**File:** `zebra-rs/src/bgp/route.rs`

1. Define `LocalRibEvpnTable`:
   ```rust
   pub struct LocalRibEvpnTable {
       pub cands: BTreeMap<EvpnPrefix, Vec<BgpRib>>, // candidate paths
       pub selected: BTreeMap<EvpnPrefix, BgpRib>,   // best path per prefix
   }
   ```
2. Mirror the methods used by the IPv4 path: `update`, `remove`,
   `remove_peer_routes`, `select_best_path`. Best-path selection delegates to
   `LocalRibTable::is_better`, which is module-private but visible to
   `LocalRibEvpnTable` since both live in `route.rs` — no API change to
   `LocalRibTable`.
3. Add field on `LocalRib`: `pub evpn: BTreeMap<RouteDistinguisher, LocalRibEvpnTable>`.
4. Add `LocalRib` dispatch helpers: `update_evpn`, `remove_evpn`,
   `remove_peer_routes_evpn`, `select_best_path_evpn`. Mirrors the existing
   `update(rd: Option<RD>, ...)` shape but takes `RouteDistinguisher` directly
   (EVPN is always RD-scoped, so the `Option` is unnecessary).

**File:** `zebra-rs/src/bgp/adj_rib.rs`

5. Define `AdjRibEvpnTable<D: RibDirection>` as a tuple struct mirroring
   `AdjRibTable<D>`, keyed on `EvpnPrefix`. `add` / `remove` use the same
   direction-aware path-id pattern (`D::get_id`) and the same `id == 0`
   sentinel for "remove all candidates" as the IPv4 table.
6. Add field on `AdjRib<D>`: `pub evpn: BTreeMap<RouteDistinguisher, AdjRibEvpnTable<D>>`.
7. Both `AdjRib<In>` and `AdjRib<Out>` impls gain `add_evpn` / `remove_evpn` /
   `contains_key_evpn`. The existing `count(afi, safi)` method gains an
   `(L2vpn, Evpn)` arm so existing callers can query EVPN counts via the same
   API.

### Step 3 — Wire into existing `LocalRib` and `AdjRib`

**Status:** Merged into Step 2 — see the status note at the top of Step 2 for
the rationale. Numbering of Steps 4–7 is preserved to keep existing
commit-message references valid.

### Step 4 — UPDATE / WITHDRAW dispatch

**Status:** Implemented in commit `e56b2c8`.

**File:** `zebra-rs/src/bgp/route.rs` (`route_from_peer`)

1. Add `MpReachAttr::Evpn { snpa, nhop, updates }` arm:
   - Store `nhop` on a per-route `BgpAttr` (reuse the existing nexthop pathway used by VPNv4).
   - For each `EvpnRoute` in `updates`: call `EvpnPrefix::from_route` to split into `(rd, prefix)`, build a `BgpRib`, insert into `peer.adj_in.evpn[rd]` and `bgp.local_rib.evpn[rd]`, then recompute best-path for that key.
2. Add the symmetric `MpUnreachAttr::Evpn(routes)` arm in the withdrawal block — same `from_route` split, then withdraw from both adj-in and loc-rib, recompute best-path.
3. Add `MpUnreachAttr::EvpnEor` arm — mark EOR for `(L2vpn, Evpn)` in the existing `peer.eor` map (already an `AfiSafi`-keyed map).

**Note on the EVPN nexthop:** the `nhop` field of `MpReachAttr::Evpn` is
passed into `route_evpn_update` but not stored on `BgpRib` — `BgpRib::new`
takes `Option<Vpnv4Nexthop>`, which is IPv4-only and RD-bound. This was
flagged as a Step 5 follow-up, but turned out to need no follow-up at all:
the attribute parser already stores the EVPN nexthop on
`bgp_attr.nexthop` as `BgpNexthop::Evpn(IpAddr)` (see
`crates/bgp-packet/src/attrs/attr.rs:345`), and `show_nexthop` already
handles that variant, so the Step 5 show command recovers the nexthop
from `rib.attr.nexthop` automatically.

### Step 5 — `show ip bgp evpn`

**Status:** Implemented in commit `866317a`. The same commit also fixes
two pre-existing test-only sites in `zebra-rs/src/rib/link.rs` that were
broken by a `netlink_packet_route::link::LinkFlags` upgrade making the
type `non_exhaustive` (replaced `LinkFlags(IFF_UP | IFF_RUNNING)` with
`LinkFlags::empty()`, since the affected tests do not read `link.flags`).
With that fix `cargo test -p zebra-rs` reports 56/56 passing including
the 3 new EVPN show tests.

**File:** `zebra-rs/src/bgp/show.rs` (replaces the empty `show_bgp_l2vpn_evpn` stub)

1. Implement `show_bgp_l2vpn_evpn()` to walk `bgp.local_rib.evpn`. Rendered output must match this layout exactly:

   ```text
   EVPN type-1 prefix: [1]:[EthTag]:[ESI]:[IPlen]:[VTEP-IP]:[Frag-id]
   EVPN type-2 prefix: [2]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]
   EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]
   EVPN type-4 prefix: [4]:[ESI]:[IPlen]:[OrigIP]
   EVPN type-5 prefix: [5]:[EthTag]:[IPlen]:[IP]

      Network          Next Hop            Metric LocPrf Weight Path
   Route Distinguisher: 10.0.0.5:2
    *>  [2]:[0]:[48]:[fe:b2:14:6c:11:6c]
                       10.0.0.5                           32768 i
                       ET:8 RT:65501:550
    *>  [3]:[0]:[32]:[10.0.0.5]
                       10.0.0.5                           32768 i
                       ET:8 RT:65501:550
   ```

   - Print the legend (5 "EVPN type-N prefix:" lines) once at the top, then the column header.
   - For each `(rd, table)` in `bgp.local_rib.evpn`, print `Route Distinguisher: <rd>` followed by routes.
   - For each `(EvpnPrefix, BgpRib)` in `table.selected`: render the `*>` flag, the prefix via its `Display`, the next-hop indented on a second line, and an indented third line for extended communities (`ET:8 RT:65501:550` style).
2. The extended-community render needs the Encapsulation extended community ("ET:N") and Route Target ("RT:asn:val"). `ExtCommunityValue` is a generic 8-byte type today; add a small formatter helper that decodes the well-known subtypes:
   - `Encapsulation` (`high_type = 0x03`, `low_type = 0x0c`) → `ET:<tunnel-type>` (tunnel-type 8 = VXLAN)
   - `RouteTarget two-octet AS` (`high_type = 0x00`, `low_type = 0x02`) → `RT:<asn>:<u32>`
   - Fallback: hex-dump for unknown subtypes.
3. Verify the show callback is registered at `/show/ip/bgp/l2vpn/evpn` (exploration suggests it already is at `show.rs:1733` — confirm and add if missing).

### Step 6 — Capability / config plumbing (small)

**Status:** No code change needed — every layer was already in place
when this branch started. The plan's exploration assumed this might be
the case ("exploration suggests yes") and turned out to be right at
every checkpoint. End-to-end trace, with file:line evidence:

| Layer | Evidence |
|---|---|
| YANG identity `l2vpn-evpn` (`base afi-safi-type`) | `zebra-rs/yang/iana-bgp-types@2023-07-05.yang:357` |
| YANG `name` leaf is `identityref { base bt:afi-safi-type; }`, so `l2vpn-evpn` validates | `zebra-rs/yang/ietf-bgp-common-multiprotocol@2023-07-05.yang:142` |
| YANG `l2vpn-evpn` container under `mp-all-afi-safi-list-contents` | `zebra-rs/yang/ietf-bgp-common-multiprotocol@2023-07-05.yang:278` |
| `args.afi_safi()` parses `"l2vpn-evpn"` → `AfiSafi { L2vpn, Evpn }` | `zebra-rs/src/config/configs.rs:135` |
| `config_afi_safi` is generic — accepts any `AfiSafi` from `args.afi_safi()` and stores it in `peer.config.mp` | `zebra-rs/src/bgp/config.rs:236` |
| `CapAfiMap::new()` pre-registers `(L2vpn, Evpn)` so send/recv flags can be tracked | `zebra-rs/src/bgp/cap.rs:40, 49` |
| `peer_send_open` iterates `peer.config.mp.0` and emits a `CapMultiProtocol` for each entry | `zebra-rs/src/bgp/peer.rs:810-812` |
| `cap_register_send` invoked after sending OPEN | `zebra-rs/src/bgp/peer.rs:839` |
| `cap_register_recv` invoked when peer's OPEN is parsed | `zebra-rs/src/bgp/peer.rs:575` |
| Per-neighbor capability display already shows `"L2VPN/EVPN"` | `zebra-rs/src/bgp/show.rs:1275, 1323, 1379, 1428` |

**End-to-end flow** for `set routing bgp neighbor X.X.X.X afi-safi l2vpn-evpn enabled true`:

1. YANG validates the identityref → command accepted.
2. Callback `/routing/bgp/neighbor/afi-safi/enabled` → `config_afi_safi`.
3. `args.afi_safi()` returns `AfiSafi { L2vpn, Evpn }`.
4. `peer.config.mp.set(key, true)`.
5. Next `peer_send_open` iterates `peer.config.mp.0` → emits
   `CapMultiProtocol(L2vpn, Evpn)` in OPEN.
6. `cap_register_send` flags `(L2vpn, Evpn)` as `send=true` in `peer.cap_map`.
7. Peer responds with their OPEN → `cap_register_recv` flags `recv=true`.
8. Subsequent EVPN UPDATE messages flow through the `MpReach::Evpn` arm
   added in Step 4 → `route_evpn_update` → `peer.adj_in.add_evpn` +
   `bgp.local_rib.update_evpn`.
9. `show ip bgp evpn` (Step 5) walks `bgp.local_rib.evpn` and displays them.

The likely reason this was already in place: the `mpevpn` line in
`cap.rs:40` and the `"l2vpn-evpn"` arm in `configs.rs:135` predate this
branch — they were added as preparatory work before the EVPN feature
was started.

### Step 7 — Build & format
1. `cargo build --bin zebra-rs` — must compile clean.
2. `cargo fmt --all`.
3. Manual smoke test: bring up two zebra-rs instances with `l2vpn-evpn` enabled; inject a Type 2 / Type 3 from one (or peer with FRR/GoBGP); verify `show ip bgp evpn` on the other matches the layout above.

---

## 4. Out of scope (explicitly, to avoid scope creep)

- **Origination of local EVPN routes** — no Type 3 auto-generation per VNI, no MAC learning bridge to a kernel bridge / FDB.
- **MAC mobility (sequence number)** for Type 2.
- **DF election** for Type 4.
- **Type 1 / Type 4 / Type 5** route handling — parsers don't exist either.
- **Encapsulation extended community origination** — only decoding/display in this slice.
- **FIB programming** — no kernel VXLAN tunnel programming, no bridge FDB sync.
- **EVI / MAC-VRF configuration model.**
- **Symmetric / asymmetric IRB.**

These are all valid follow-up work but each deserves its own design.

---

## 5. Open questions

1. **Path-id / AddPath for EVPN.** `EvpnMac` already has an `id` field in the parser. Should the EVPN RIB key include the path-id (so multiple paths to the same `(RD, EvpnPrefix)` from one peer coexist), or should it be treated like the existing IPv4 path where AddPath multiplies entries inside the `Vec<BgpRib>`? **Default:** the latter (consistency with `Ipv4Nlri.id`), unless there is a reason to deviate.
2. **Where should `EvpnPrefix` live** — in `crates/bgp-packet` next to `EvpnRoute`, or in `zebra-rs/src/bgp/` as a RIB-side concern? **Default:** `bgp-packet`, so other consumers of the crate can use it; this is a coupling decision worth a sanity check.
3. **MAC `Display` format** — confirmed lowercase hex with colons (`fe:b2:14:6c:11:6c`).
4. **Ordering of routes within an RD in the show output** — sort by `(route_type, eth_tag, mac_or_ip)` lexicographically. Falls out naturally from `BTreeMap<EvpnPrefix, _>` if `EvpnPrefix` derives `Ord` with route-type-first variant order.

---

## 6. Files touched (summary)

| File | Change |
|---|---|
| `crates/bgp-packet/src/attrs/nlri_evpn.rs` | Add `EvpnPrefix` enum + `Display` + `from_route` |
| `crates/bgp-packet/src/attrs/mp_reach.rs` | Remove stray `println!` at line 137 |
| `zebra-rs/src/bgp/route.rs` | Add `LocalRibEvpnTable`, wire `LocalRib.evpn`, dispatch in `route_update` |
| `zebra-rs/src/bgp/adj_rib.rs` | Add `AdjRibEvpnTable<D>`, wire `AdjRib.evpn` |
| `zebra-rs/src/bgp/show.rs` | Implement `show_bgp_l2vpn_evpn` (currently empty stub) |
| `zebra-rs/src/bgp/config.rs` | (If needed) `config_afi_safi` arm for `l2vpn-evpn` |
| `zebra-rs/yang/...` | (If needed) add `l2vpn-evpn` to the AFI/SAFI enum |

Net new types: `EvpnPrefix`, `LocalRibEvpnTable`, `AdjRibEvpnTable<D>`. No changes to `BgpRib`, `BgpAttr`, `Peer`, FSM, or kernel/FIB layers.
