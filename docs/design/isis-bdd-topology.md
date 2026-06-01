# IS-IS BDD Test Topology

Blueprint for the IS-IS behaviour-driven tests under `bdd/`. One 10-router
logical graph is reused across a **3 × 3 matrix**: three level modes
(`level-1-only`, `level-2-only`, `level-1-2 mixed`) × three link media
(all point-to-point, all LAN/broadcast, mixed). Addressing is **dual-stack**
(IPv4 + IPv6). This document is the source of truth the per-router config
YAMLs and `.feature` files are generated from.

## 1. The matrix

|              | all P2P            | all LAN            | mixed P2P+LAN      |
|--------------|--------------------|--------------------|--------------------|
| **L1-only**  | `isis_l1_p2p`      | `isis_l1_lan`      | `isis_l1_mixed`    |
| **L2-only**  | `isis_l2_p2p`      | `isis_l2_lan`      | `isis_l2_mixed`    |
| **L1L2 mix** | `isis_l1l2_p2p`    | `isis_l1l2_lan`    | `isis_l1l2_mixed`  |

Tags above double as cucumber `@feature_tag`s and the
`bdd/tests/configs/<tag>/` directory names. The *logical graph, metrics,
system-IDs and addressing are identical across all nine* — only `network-type`
(per link medium), `is-type` + per-interface `circuit-type` (per level mode),
and the NET `area` (mixed mode) change.

## 2. Base graph — the "2 × 5 ladder"

```
  z1 ──10── z2 ──10── z3 ──10── z4 ──10── z5      top spine    (metric 10)
  │         │         │         │         │
  40        30        30        30        40       rungs        (40 ends / 30 mid)
  │         │         │         │         │
  z6 ──20── z7 ──20── z8 ──20── z9 ──20── z10     bottom spine (metric 20)
```

Ten zebra-rs instances, namespaces `z1`…`z10`. Every node has a clean
**primary** path along its spine and a **backup** out a *different* interface
via a rung — which is exactly the "primary and backup through a different
interface" requirement, and gives deterministic interface-down failover.

Asymmetric spine metrics (top 10 ≠ bottom 20) deliberately break the
diagonal ties that an even ladder would create, so the topology is **almost
entirely primary/backup** with just **two intentional ECMP diamonds** (§4).

## 3. Nodes, interfaces, addressing (dual-stack)

Interface convention: on `zI`, the link toward `zJ` is named **`iJ`**. The
router with the smaller index owns host `.1` / `::1` on each link subnet, the
larger owns `.2` / `::2`.

### Loopbacks (ping targets)

| Node | IPv4 (`lo`)   | IPv6 (`lo`)              | IS-IS system-id   |
|------|---------------|--------------------------|-------------------|
| z1   | 10.0.0.1/32   | 2001:db8:0:ffff::1/128   | 0000.0000.0001    |
| z2   | 10.0.0.2/32   | 2001:db8:0:ffff::2/128   | 0000.0000.0002    |
| z3   | 10.0.0.3/32   | 2001:db8:0:ffff::3/128   | 0000.0000.0003    |
| z4   | 10.0.0.4/32   | 2001:db8:0:ffff::4/128   | 0000.0000.0004    |
| z5   | 10.0.0.5/32   | 2001:db8:0:ffff::5/128   | 0000.0000.0005    |
| z6   | 10.0.0.6/32   | 2001:db8:0:ffff::6/128   | 0000.0000.0006    |
| z7   | 10.0.0.7/32   | 2001:db8:0:ffff::7/128   | 0000.0000.0007    |
| z8   | 10.0.0.8/32   | 2001:db8:0:ffff::8/128   | 0000.0000.0008    |
| z9   | 10.0.0.9/32   | 2001:db8:0:ffff::9/128   | 0000.0000.0009    |
| z10  | 10.0.0.10/32  | 2001:db8:0:ffff::10/128  | 0000.0000.0010    |

### Links (13 total)

| # | Endpoints | Role        | Metric | IPv4 /30      | IPv6 /64          |
|---|-----------|-------------|:------:|---------------|-------------------|
| L1  | z1–z2   | top spine   | 10 | 10.0.1.0/30  | 2001:db8:1::/64  |
| L2  | z2–z3   | top spine   | 10 | 10.0.2.0/30  | 2001:db8:2::/64  |
| L3  | z3–z4   | top spine   | 10 | 10.0.3.0/30  | 2001:db8:3::/64  |
| L4  | z4–z5   | top spine   | 10 | 10.0.4.0/30  | 2001:db8:4::/64  |
| L5  | z6–z7   | bottom spine| 20 | 10.0.5.0/30  | 2001:db8:5::/64  |
| L6  | z7–z8   | bottom spine| 20 | 10.0.6.0/30  | 2001:db8:6::/64  |
| L7  | z8–z9   | bottom spine| 20 | 10.0.7.0/30  | 2001:db8:7::/64  |
| L8  | z9–z10  | bottom spine| 20 | 10.0.8.0/30  | 2001:db8:8::/64  |
| L9  | z1–z6   | **end rung**| 40 | 10.0.9.0/30  | 2001:db8:9::/64  |
| L10 | z2–z7   | mid rung    | 30 | 10.0.10.0/30 | 2001:db8:10::/64 |
| L11 | z3–z8   | mid rung    | 30 | 10.0.11.0/30 | 2001:db8:11::/64 |
| L12 | z4–z9   | mid rung    | 30 | 10.0.12.0/30 | 2001:db8:12::/64 |
| L13 | z5–z10  | **end rung**| 40 | 10.0.13.0/30 | 2001:db8:13::/64 |

### Per-node interface list

| Node | Interfaces (name → link)                           |
|------|----------------------------------------------------|
| z1   | i2→L1, i6→L9                                        |
| z2   | i1→L1, i3→L2, i7→L10                                |
| z3   | i2→L2, i4→L3, i8→L11                                |
| z4   | i3→L3, i5→L4, i9→L12                                |
| z5   | i4→L4, i10→L13                                      |
| z6   | i1→L9, i7→L5                                        |
| z7   | i6→L5, i8→L6, i2→L10                                |
| z8   | i7→L6, i9→L7, i3→L11                                |
| z9   | i8→L7, i10→L8, i4→L12                               |
| z10  | i9→L8, i5→L13                                       |

## 4. Metric plan & the two ECMP diamonds

Base metrics: top spine **10**, bottom spine **20**, mid rungs **30**, **end
rungs 40**. With this scheme there is *no* ECMP anywhere — every destination
resolves to a single primary plus a strictly costlier backup.

The two **end rungs are set to 40** (vs 30 mid) specifically to re-introduce
**exactly two ECMP diamonds**, one at each end of the ladder:

**Left diamond — z2 ↔ z6** (`{1,2,6,7}` square):
- `z2 → z6`: via `i1` (z2-z1-z6 = 10+40 = 50) **==** via `i7` (z2-z7-z6 = 30+20 = 50) → ECMP `{i1, i7}`.
- `z6 → z2`: via `i1` (z6-z1-z2 = 40+10 = 50) **==** via `i7` (z6-z7-z2 = 20+30 = 50) → ECMP `{i1, i7}`.

**Right diamond — z4 ↔ z10** (`{4,5,9,10}` square):
- `z4 → z10`: via `i5` (z4-z5-z10 = 10+40 = 50) **==** via `i9` (z4-z9-z10 = 30+20 = 50) → ECMP `{i5, i9}`.
- `z10 → z4`: via `i5` (z10-z5-z4 = 40+10 = 50) **==** via `i9` (z10-z9-z4 = 20+30 = 50) → ECMP `{i5, i9}`.

These are the **only** ties in the flat (L1-only / L2-only) topologies — all
other diagonal candidates are eliminated by `top(10) ≠ bottom(20)`, and the
ties are localized: e.g. `z3 → z6` installs a single next-hop (`i2`) and the
ECMP only appears once traffic reaches z2. "Mixed metric" requirement is met
by the four tiers (10/20/30/40).

## 5. Expected forwarding (flat topologies)

Representative assertions (destination = peer loopback):

| From | To  | Primary (cost / iface) | Backup after primary iface down (cost / iface) |
|------|-----|------------------------|------------------------------------------------|
| z1   | z3  | 20 / `i2`              | 100 / `i6`                                     |
| z1   | z5  | 40 / `i2`              | 120 / `i6`                                     |
| z6   | z10 | 80 / `i7`              | 120 / `i1`                                     |
| z3   | z8  | 30 / `i8` (rung)       | 60 / `{i2, i4}`                                |
| z2   | z6  | **ECMP 50 / `{i1,i7}`**| n/a (dual next-hop)                            |
| z4   | z10 | **ECMP 50 / `{i5,i9}`**| n/a (dual next-hop)                            |

Costs above are from a Dijkstra over the actual link metrics. Backups are
much costlier than primaries (a downed primary climbs back to the cheap top
spine via the nearest rung), so the primary is unambiguously preferred and an
interface-down event produces a clear, testable reconvergence onto a
*different* egress interface. (`z3 → z8`'s backup is itself a 60-cost ECMP
pair `{i2, i4}` — harmless, just noted for accuracy.)

## 6. Level / area assignment per mode

System-ids (§3) are constant across modes. Only NET `area`, `is-type`, and
per-interface `circuit-type` change.

- **L1-only**: single area **49.0001**; every node `is-type level-1`; every
  interface `circuit-type level-1`. NET = `49.0001.0000.0000.000I.00`.
- **L2-only**: single area **49.0001**; every node `is-type level-2-only`;
  every interface `circuit-type level-2-only`. (Matches the existing
  `isis_ipv6` feature.)
- **L1L2 mixed**: two L1 areas joined by an L2 backbone.

  | Node      | Area    | is-type        | Per-interface circuit-type            |
  |-----------|---------|----------------|---------------------------------------|
  | z1        | 49.0001 | level-1        | i2,i6 = level-1                       |
  | z6        | 49.0001 | level-1        | i1,i7 = level-1                       |
  | z2        | 49.0001 | level-1-2      | i1,i7 = level-1; i3 = level-2-only    |
  | z7        | 49.0001 | level-1-2      | i6,i2 = level-1; i8 = level-2-only    |
  | z3        | 49.0000 | level-2-only   | i2,i4,i8 = level-2-only               |
  | z8        | 49.0000 | level-2-only   | i7,i9,i3 = level-2-only               |
  | z4        | 49.0002 | level-1-2      | i3 = level-2-only; i5,i9 = level-1    |
  | z9        | 49.0002 | level-1-2      | i8 = level-2-only; i10,i4 = level-1   |
  | z5        | 49.0002 | level-1        | i4,i10 = level-1                      |
  | z10       | 49.0002 | level-1        | i9,i5 = level-1                       |

  - L1 area **0001** = {z1,z2,z6,z7} (intra links L1, L5, L9, L10).
  - L1 area **0002** = {z4,z5,z9,z10} (intra links L4, L8, L12, L13).
  - L2 backbone = {z2,z7,z3,z8,z4,z9} (links L2, L6, L3, L7, **L11** the
    z3-z8 rung bridges top/bottom → contiguous backbone).
  - z2/z7 (area 0001) and z4/z9 (area 0002) are the L1L2 border routers;
    z3/z8 are pure backbone. L1 routers reach remote areas via the
    nearest-L1L2 default route (ATT bit). The detailed inter-area path table
    is computed at config-generation time since it follows L1 default-route
    semantics rather than the flat SPF above.

## 7. Link-medium realization per variant

The logical adjacency graph is identical; only the L2 medium + IS-IS
`network-type` differ.

- **all P2P**: each of the 13 links is a direct veth pair
  (`connect_netns_pair`), `network-type point-to-point`. **No new harness
  step needed.**
- **all LAN**: each link is its own 2-router bridge, `network-type lan`
  (DIS elected + pseudonode LSP per segment).
- **mixed**: spines (L1–L8) stay P2P; rungs (L9–L13) become LAN. (Or another
  split — TBD; documented so assertions stay deterministic.)

### Harness work this requires (tracked, not yet built)

1. **New step — attach a named interface to a bridge.** Current bridge steps
   bind exactly one veth per namespace (`v{ns}ns`); a 10-router LAN/mixed
   topology needs `I connect namespace "zI" interface "iJ" to bridge "brX"`.
2. ~~**New step — IPv4 ping.**~~ **DONE** (`isis_l1_p2p` slice). `ping6`/`ping4`
   now share a `ping_family` helper in `bdd/src/netns.rs`, and the existing
   `ping from "zI" to "<addr>" should succeed/fail` steps pick the family from
   the target literal (`:` → IPv6, else IPv4), so one step covers dual-stack.
3. **Generalize `the test topology exists`.** It is hard-coded to z1/z2;
   z1/z2 still exist here so it passes, but it should check the routers a
   scenario actually uses (or scenarios stay self-contained).
4. IPv4 / route-table assertions can reuse the existing generic
   `show command "..." in namespace "zI" should contain "..."` step.

## 8. Open decisions

- **LAN segment depth.** Baseline keeps every link a 2-router broadcast
  segment so the graph (and therefore the §4/§5 path analysis) is *identical*
  across all nine realizations. A 2-router segment still exercises DIS
  election + pseudonode LSPs but not "a third router learning the segment via
  the DIS." Promoting one or two segments to genuine ≥3-router LANs would
  deepen DIS coverage but adds adjacencies not present in the P2P graph and
  forks the path analysis for those variants. **Recommendation: keep 2-router
  segments for parity; add a dedicated 3-router-LAN scenario later if deeper
  DIS coverage is wanted.**
- **Mixed-variant link split.** Spines-P2P / rungs-LAN (above) vs odd/even vs
  per-row. Pick the one that best exercises a P2P↔LAN boundary on the same
  router.
- **Build order.** First slice = `isis_l1_p2p` (no harness change); then the
  LAN harness step unlocks the rest of the matrix.
