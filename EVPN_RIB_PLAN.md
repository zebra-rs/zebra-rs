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
**File:** `crates/bgp-packet/src/attrs/nlri_evpn.rs`

1. Add `EvpnPrefix` enum (D1) with `MacIp` and `InclusiveMulticast` variants. Derive `Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash`.
2. Implement `Display for EvpnPrefix` matching the user-specified format:
   - Type 2 without IP: `[2]:[<ethtag>]:[48]:[mac]`
   - Type 2 with IP: `[2]:[<ethtag>]:[48]:[mac]:[<iplen>]:[<ip>]`
   - Type 3: `[3]:[<ethtag>]:[<iplen>]:[<orig>]`
   - MAC formatted as lowercase hex with colons: `fe:b2:14:6c:11:6c`.
3. Implement `EvpnPrefix::from_route(&EvpnRoute) -> (RouteDistinguisher, EvpnPrefix)`.
4. **Cleanup:** remove the stray `println!` at `crates/bgp-packet/src/attrs/mp_reach.rs:137`.

### Step 2 — New RIB table types
**File:** `zebra-rs/src/bgp/route.rs` (or split out into `zebra-rs/src/bgp/route_evpn.rs` for clarity)

1. Define `LocalRibEvpnTable`:
   ```rust
   pub struct LocalRibEvpnTable {
       pub ribs: BTreeMap<EvpnPrefix, Vec<BgpRib>>, // candidate paths
       pub selected: BTreeMap<EvpnPrefix, BgpRib>,  // best path per prefix
   }
   ```
2. Mirror the methods used by the IPv4 path: `update`, `withdraw`, `iter`, `len`, `clear`, `select_best`. Implementations are direct ports replacing `PrefixMap` with `BTreeMap`.

**File:** `zebra-rs/src/bgp/adj_rib.rs`

3. Define `AdjRibEvpnTable<D: RibDirection>`:
   ```rust
   pub struct AdjRibEvpnTable<D: RibDirection> {
       pub map: BTreeMap<EvpnPrefix, Vec<BgpRib>>,
       _phantom: PhantomData<D>,
   }
   ```

### Step 3 — Wire into existing `LocalRib` and `AdjRib`

**File:** `zebra-rs/src/bgp/route.rs:355` (`LocalRib`)
- Add field: `pub evpn: BTreeMap<RouteDistinguisher, LocalRibEvpnTable>`.
- Add `LocalRib::update_evpn(&mut self, rd, prefix, rib)` and `withdraw_evpn` helpers, mirroring the existing `update(rd: Option<RD>, ...)` shape. Initialize the per-RD `LocalRibEvpnTable` lazily.

**File:** `zebra-rs/src/bgp/adj_rib.rs:92` (`AdjRib<D>`)
- Add field: `pub evpn: BTreeMap<RouteDistinguisher, AdjRibEvpnTable<D>>` plus parallel helpers.

### Step 4 — UPDATE / WITHDRAW dispatch
**File:** `zebra-rs/src/bgp/route.rs:878` (`route_update`)

1. Add `MpReachAttr::Evpn { snpa, nhop, updates }` arm:
   - Store `nhop` on a per-route `BgpAttr` (reuse the existing nexthop pathway used by VPNv4).
   - For each `EvpnRoute` in `updates`: call `EvpnPrefix::from_route` to split into `(rd, prefix)`, build a `BgpRib`, insert into `peer.adj_in.evpn[rd]` and `bgp.local_rib.evpn[rd]`, then recompute best-path for that key.
2. Add the symmetric `MpUnreachAttr::Evpn(routes)` arm in the withdrawal block — same `from_route` split, then withdraw from both adj-in and loc-rib, recompute best-path.
3. Add `MpUnreachAttr::EvpnEor` arm — mark EOR for `(L2vpn, Evpn)` in the existing `peer.eor` map (already an `AfiSafi`-keyed map).

### Step 5 — `show ip bgp evpn`
**File:** `zebra-rs/src/bgp/show.rs:1639` (existing empty stub)

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

For the initial slice, no per-peer config UI changes are strictly required: `LocalRib::evpn` will simply remain empty for any peer that does not negotiate `(L2vpn, Evpn)`. However, for the feature to be actually exercised end-to-end:

1. Verify `cap_register_send` / `cap_register_recv` in `crates/bgp-packet/src/bgp_cap.rs` already round-trips `(Afi::L2vpn, Safi::Evpn)` via the generic `CapMultiProtocol` path. (Exploration suggests yes.)
2. Add a config handler arm in `config_afi_safi` that accepts `l2vpn-evpn` so users can enable it via `set routing bgp neighbor X.X.X.X afi-safi l2vpn-evpn enabled true`.
3. **Verify the YANG `afi-safi` enum allows `l2vpn-evpn` before writing the handler** — if not, add it to the relevant YANG file under `zebra-rs/yang/`.

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
