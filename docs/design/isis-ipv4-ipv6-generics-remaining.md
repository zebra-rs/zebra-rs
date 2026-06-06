# IS-IS IPv4/IPv6 Generics — Remaining Items

Branch: `isis-ipv4-ipv6-generics`

## Completed (Items 1–9)

| # | What | Files |
|---|------|-------|
| 1–4 | `SpfRoute<F>`, `SpfNexthop<F>`, `make_rib_entry<F>`, `diff_apply<F>`, `DiffResult<F>` | `rib.rs` |
| 5 | `ReachMap<E>` generic + `ReachMapV4`/`ReachMapV6` aliases; manual `Default` | `graph.rs`, `inst.rs`, `lsdb.rs`, `link.rs` |
| 6 | `summarize_frr<F>` (adds `backup_sr_len` to `IsisRibFamily`) | `show.rs`, `rib.rs` |
| 7 | `write_rib_detail<F>` | `show.rs` |
| 8 | `write_rib_table<F>` + `IsisRibFamilyShow` trait (`W_PREFIX`, `W_NEXTHOP`, `label_col`) | `show.rs` |
| 9 | `write_isis_nhop_detail<F>` (`write_nhop_extra`, `write_sid_block`, `write_backup`) | `show.rs` |

---

## Remaining Items

### Item 10 — `build_rib_from_spf` / `build_rib_from_spf_v6`

**File:** `rib.rs:647` and `rib.rs:894`  
**Difficulty:** Hard

The two biggest functions in `rib.rs`. Structurally identical loop shape (walk SPF result, build nhop map, merge reach entries by metric, post-loop TI-LFA backup pass) but with these differences:

| Aspect | V4 | V6 |
|--------|----|----|
| Extra parameter | — | `mt2_mode: bool` |
| Reach map | `top.reach_map.get(level).get(&Afi::Ip).get(sys_id)` | `top.reach_map_v6` or `top.mt2_reach_map_v6` |
| NLPID gating | None | `ipv6_capable_set` gate per RFC 1195 §5 (legacy mode only) |
| Nexthop addresses | `nbr.addr4.iter()` keys | `nbr.addr6l.iter()` |
| Prefix-SID | Full SRGB lookup → `sid`/`prefix_sid`/`no_php` | All `None` (deferred) |
| TI-LFA backup | `build_repair_path_mpls` | `build_repair_path_srv6` |

**Suggested approach:**  
Extend `IsisRibFamily` with:

```rust
// Address iterator over the neighbor's addresses for this family.
fn nhop_addrs<'a>(nbr: &'a Nbr) -> impl Iterator<Item = &'a Self::Addr>;

// Reach entries for `sys_id` in the given reach map.
fn reach_entries<'a>(
    top: &'a IsisTop,
    level: Level,
    sys_id: &IsisSysId,
    mt2_mode: bool,
) -> Option<&'a Vec<…>>;

// Resolve Prefix-SID to absolute label (None for V6 until SRv6 Prefix-SID lands).
fn resolve_sid(
    top: &IsisTop,
    level: Level,
    sys_id: &IsisSysId,
    entry: &Self::TlvEntry,
) -> (Option<u32>, Option<(SidLabelValue, LabelConfig)>, bool); // (sid, prefix_sid, no_php)

// Build TI-LFA repair path.
fn build_repair_path(
    top: &mut IsisTop,
    level: Level,
    repair: &spf::RepairPath,
) -> Option<Self::Backup>;
```

Then `build_rib_from_spf<F: IsisRibFamily>` takes an additional `mt2_mode: bool` and is
generic over `F`.

**Complication:** The NLPID gating loop (`'next_path:` with per-hop IPv6 check) is V6-only.
The cleanest route is to move it into a family-specific `filter_path` trait method:
```rust
fn path_allowed(top: &IsisTop, level: Level, p: &[usize], mt2_mode: bool) -> bool;
```
`V4` returns `true` unconditionally; `V6` does the NLPID walk.

The `TlvEntry` associated type (`IsisTlvExtIpReachEntry` vs `IsisTlvIpv6ReachEntry`) is the
trickiest bound — both need `prefix()`, `metric()`, and optionally `prefix_sid()`.
Either introduce a `ReachEntry` trait in `isis_packet`, or keep the entry-specific SID
plumbing behind the `resolve_sid` trait method and pass the entry as `&dyn Any` (unclean) —
prefer the trait.

---

### Item 11 — `ipv4_reach` / `ipv6_reach` in `bgp_ls.rs`

**File:** `bgp_ls.rs:57` and `bgp_ls.rs:67`  
**Difficulty:** Easy

Bodies are byte-for-byte identical; only the input type differs (`Ipv4Net` vs `Ipv6Net`).
Unify into a single `ip_reach(net: IpNet) -> LsPrefixDescriptor` using the `ipnet::IpNet`
enum (both `Ipv4Net` and `Ipv6Net` implement `Into<IpNet>`):

```rust
fn ip_reach(net: IpNet) -> LsPrefixDescriptor {
    let prefix_len = net.prefix_len();
    let nbytes = prefix_len.div_ceil(8) as usize;
    let octets: Vec<u8> = match net {
        IpNet::V4(n) => n.network().octets().to_vec(),
        IpNet::V6(n) => n.network().octets().to_vec(),
    };
    LsPrefixDescriptor::IpReachability { prefix_len, prefix: octets[..nbytes].to_vec() }
}
```

Call sites change from `ipv4_reach(&e.prefix)` / `ipv6_reach(&e.prefix)` to
`ip_reach(e.prefix.into())`.

---

### Item 12 — `ipv4_prefix_object` / `ipv6_prefix_object` in `bgp_ls.rs`

**File:** `bgp_ls.rs:138` and `bgp_ls.rs:152`  
**Difficulty:** Easy

Differ only in the NLRI variant (`Ipv4Prefix` vs `Ipv6Prefix`) and the inner descriptor
function (`ipv4_reach` → `ip_reach` after Item 11).  Can be unified once Item 11 is done:

```rust
fn prefix_object(
    proto: LsProtocolId,
    local: &IsisSysId,
    net: IpNet,
    metric: u32,
) -> Object {
    let nlri_variant = match net {
        IpNet::V4(_) => |inner| BgpLsNlri::Ipv4Prefix(inner),
        IpNet::V6(_) => |inner| BgpLsNlri::Ipv6Prefix(inner),
    };
    let nlri = nlri_variant(LsPrefixNlri {
        protocol_id: proto,
        identifier: 0,
        local_node: node_descriptor(local),
        prefix_descs: vec![ip_reach(net)],
    });
    (nlri, prefix_attr(metric))
}
```

Items 11 and 12 are best done together in one PR since they're both in `bgp_ls.rs`.

---

## Suggested Order

```
Items 11+12  (bgp_ls.rs — trivial, isolated, low-risk)
Item 10      (rib.rs — the big one; do last, needs trait extension design)
```

Item 10 is the last significant duplication.  After it lands the codebase will have a
single generic `build_rib_from_spf<F>` that covers both address families and MT-2 mode.
