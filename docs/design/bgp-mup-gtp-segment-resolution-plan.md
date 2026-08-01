# BGP MUP — explicit interwork/direct segment resolution for `dataplane gtp`

> **Status:** COMPLETE (2026-08-01), including the final extensions.
> Stages 1–5 merged (zebra #2206/#2207/#2208/#2209/#2210, cradle
> #170/#171/#172); stage 6's knobs (`lookup-network-instance` #2212 +
> cradle #174, SID-less segment origination #2212) merged; and the two
> items originally out of scope are now implemented too — **GTP6** (v6
> outer: cradle `GTP_PDR6`/`GTP6_ENCAP`, zebra family-wide seam, UDP
> zero-checksum tunnel mode per RFC 6935/6936) and the **N9/SRGW
> composite** (a `dataplane gtp` VRF steers via REMOTE SRv6 segments:
> ST1→received-ISD H.Encaps for the UE prefix with local-catalog
> precedence, ST2→received-DSD default H.Encaps routes for decapped
> uplink; N9 GTP-toward-a-GTP-peer is the emergent fallback — a SID-less
> remote segment yields no SRv6 steer, so the outer resolves by ordinary
> FIB). Proven by `@cradle_gtp6`, `@cradle_mup_gtp6_zebra` and
> `bgp_mup_srgw_gtp`. Every PR was independently shippable and the
> single-N6 lab stayed green at each stage. Implementation notes from
> verification are folded into §3.4 and Stages 4–6 below.
>
> Origin: design review of the single-N6 configuration (`bdd/mup-lab`,
> issue #1947 arc). The `dataplane gtp` datapath hard-codes three forwarding
> contexts that the MUP architecture (draft-ietf-bess-mup-safi) derives from
> segment routes: where GTP-U is matched, which table the decapped inner
> packet is looked up in, and which table the encapped outer packet is
> resolved in. This plan makes all three explicit — interwork segment = N3
> VRF, direct segment = N6 VRF — with defaults that keep today's
> configurations working unchanged.
>
> Related: [`bgp-mup-dataplane-plan.md`](bgp-mup-dataplane-plan.md) (Plan B —
> the GTP datapath this plan refines), [`bgp-mup-followups.md`](bgp-mup-followups.md).

---

## 1. Where we are — the three implicit contexts

With `dataplane gtp`, the per-VRF reconcilers program cradle directly from the
ST routes' own fields. The segment-discovery machinery (ISD/DSD, the MUP
Extended Community 0x0c) is **not consulted** — it drives only the `end-dt46`
dataplane for *received* segment routes (`reconcile_mup_st1_isd` /
`reconcile_mup_st2_dsd`, `bgp/vrf/inst.rs:883/1003`). Instead:

| Question | Architecture source | Today (implicit) | Where |
|---|---|---|---|
| In which context does GTP-U match? | ST2's location (the interwork/N3 VRF) | **Unscoped**: `GTP_PDR` is one global map keyed `(outer dst, TEID)`, consulted in XDP on every L3 port, before any FIB lookup | zebra `reconcile_mup_gtp_uplink` `bgp/vrf/inst.rs:1089`; cradle `try_gtp_xdp` `cradle-ebpf/src/main.rs:3524-3607` |
| Which table after decap? | ST2's MUP-EC → matching DSD → direct segment (N6) | The **`route st2` binding VRF's** table (`pdr.vrf_id = ctx.vrf_id()`) | `bgp/vrf/inst.rs:1124-1128`; consumed `main.rs:3594-3605` |
| Which table after encap? | ST1 endpoint → covering ISD → interwork segment (N3) | The **global table, hard-coded**: gNB endpoint NHT registers with `vrf_id: 0`; resolved `(gw, oif)` is baked into the cradle nexthop; the eBPF never looks the outer packet up | `mup_endpoint_track_cache` `bgp/route.rs:3350-3354`; `gtp_encap` → `l2_xmit` `main.rs:2516-2561` |

Semantically, the `route st1` + `route st2` binding VRF is therefore the **de
facto direct segment (N6)** — it is both the ST1 FIB home and the decap
target — while the **interwork segment (N3) is frozen to "the global
table"**. The single-N6 lab (`mobile` VRF binds both directions, `mun3` in the
global table) is exactly the degenerate case where these implicits coincide.

Consequences beyond purity:

* A **faithful** configuration (ST2 bound to an N3 VRF) would misbehave: the
  decap would dump inner packets into the *N3* table.
* **N3 inside a kernel VRF is impossible** — three independent blockers:
  the unscoped match, the hard-coded `vrf_id: 0` endpoint resolution, and the
  cradle TC precedence where the ingress **port's** VRF overrides the decap
  metadata (`main.rs:1835-1838`, the reason for the "keep the N3 port in
  VRF 0" invariant). This is also the weak point of the Kubernetes/Multus
  answer in the book.
* **Cross-VRF `(endpoint, TEID)` collisions**: two slices/VRFs installing the
  same key in the one global `GTP_PDR` map are last-writer-wins, and
  `CradleGtpPdrDel { dst, teid }` from either VRF removes the shared entry.

## 2. Target model

The architecture mapping we implement (per draft-ietf-bess-mup-safi and the
design discussion):

* **Interwork segment = the N3 VRF** (or the global table as the degenerate
  case). **Direct segment = the N6 VRF.**
* **ST1** (UE prefix, downlink) lives in the **N6 VRF** — bound there for
  origination (RD-origin self-import already lands it, PR #1691) or pulled by
  `mup route-target import`.
* **ST2** (UPF endpoint + TEID, uplink) lives in the **N3 VRF** — its VRF is
  the GTP-U **match context**.
* **ST1 resolution**: the ST1's GTP endpoint (gNB) falls inside an
  **interwork segment's prefix** (the ISD content) → the post-encap outer
  lookup context is that segment's VRF.
* **ST2 resolution**: the ST2's **MUP Extended Community (Direct-Type Segment
  Identifier)** matches a **direct segment's** `mup-ext-comm` (the DSD
  content) → the decap target is that segment's VRF table.

No new grammar is needed for the core: `segment direct { mup-ext-comm }`,
`segment interwork { prefix }`, `route st2 { mup-ext-comm }` and the top-level
`vrf <v> mup route-target import/export` already carry every correlation
handle. What changes is their **semantics**: `segment direct` / `segment
interwork` stop being *advertisement-only* knobs and additionally declare
"this VRF **is** a direct / interwork segment" for the local datapath.

### The faithful two-VRF UPF (target configuration)

```
interface mun3 { vrf N3; ipv4 { address 10.0.12.2/24; } }   # N3 may now be a VRF
interface mun6 { vrf N6; ipv4 { address 10.0.60.1/24; } }

router bgp {
  vrf N3 {
    rd 65000:3;
    afi-safi mup {
      dataplane gtp;
      segment interwork { prefix 10.0.1.0/24; }   # gNB N3 network
      route st2 { network-instance internet; mup-ext-comm 1:6; }
    }
  }
  vrf N6 {
    rd 65000:6;
    afi-safi mup {
      dataplane gtp;
      segment direct { mup-ext-comm 1:6; }        # Direct-segment id
      route st1 { network-instance internet; }
    }
  }
  mup-c { ... }
}
```

* Downlink: packet arrives in N6 → ST1 UE route (N6 table) → GTP encap; the
  endpoint `10.0.1.x` ∈ `10.0.1.0/24` (N3's interwork prefix) → outer
  `(gw, oif)` resolved in **N3's table**.
* Uplink: G-PDU arrives on a port bound to N3 → PDR match scoped to **N3's
  table** → decap; ST2's `mup:1:6` matches N6's Direct-segment id → inner
  lookup in **N6's table**.

### Defaults — today's configs stay valid

| Situation | Resolution |
|---|---|
| ST1's endpoint covered by no interwork segment | outer context = **global table** (today's behavior) |
| ST2 with no `mup-ext-comm`, or no direct segment matches it | decap target = **the VRF holding the ST2** (today's behavior) |
| The ST2-holding VRF is not `segment interwork` | match context = **VRF 0** (today's effective behavior: N3 in the global table) |

The single-N6 `mobile` config (both `route` entries, no `segment` entries,
N3 port in VRF 0) resolves identically to today under these rules — it is the
degenerate case, and remains the recommended simple shape.

## 3. Design elements

### 3.1 The MUP segment catalog (config-derived, not route-derived)

Local resolution reads a **catalog derived from configuration**, not from the
BGP segment routes:

```rust
/// Pushed to every MUP VRF task; recomputed by the global task.
pub struct MupSegmentCatalog {
    /// Interwork segments: (covering prefix, VRF name, kernel table id).
    pub interwork: Vec<(IpNet, String, u32)>,
    /// Direct segments: (Direct-segment id, VRF name, kernel table id).
    pub direct: Vec<(RouteDistinguisher, String, u32)>,
}
```

Sources: `BgpVrfConfig.mobile_uplane.{segment, interwork_prefix, mup_ext_comm}`
(`bgp/vrf_config.rs:266-298`) + kernel table ids from `rib_known_vrfs`
(`RibKnownVrf.table_id`, `bgp/inst.rs:474`). The global task recomputes it at
`CommitEnd` and on `VrfAdd`/table-id arrival, and pushes a diff-gated
`BgpVrfMsg::MupSegmentCatalog` to the per-VRF tasks (same spawn-time +
update pattern as the existing `BgpVrf.dataplane` field,
`bgp/vrf/inst.rs:77-80`); receipt re-runs `reconcile_mup_gtp`.

Why config, not the local_rib segment routes:

* Works on a **GTP-only box with no SRv6 locator** — DSD/ISD *origination* is
  gated on `encapsulation srv6` + a carved End.DT46 SID
  (`compute_mup_segment_desired`, `bgp/route.rs:14643`), and this plan does
  not relax that. The BGP routes remain the **inter-node advertisement** of
  the same facts; the catalog is their local materialization.
* On one box, "import the N3 VRF's ISD into N6 and resolve the ST1 against
  it" and "look the endpoint up in the interwork catalog" compute the same
  answer; the catalog avoids requiring RT-import config for the collocated
  case.
* A **remote** ISD/DSD in a `dataplane gtp` VRF (GTP encap toward a *remote*
  interwork segment — the split-SRGW / N9 case) stays out of scope
  (§6); remote segments keep driving the `end-dt46` H.Encaps reconcilers.

#### The one deliberate divergence — catalog selection is not import-gated

**Open decision, flagged for review.** Under the strictest reading of the
architecture, ST resolution is gated on the segment route being *present in
the resolving VRF's RIB*: the ST1 resolves only against an ISD imported into
the N6 VRF, the ST2 only against a DSD imported into the N3 VRF (via
`mup route-target import`). This plan instead selects the interwork/direct
VRF from the **config catalog** — global configuration knowledge — without
requiring the corresponding ISD/DSD to have been originated or imported into
the holding VRF's `local_rib`.

On a single box the two compute the same answer; the divergence is only that
the catalog also resolves when the operator has configured **no** MUP RTs
(the collocated common case) or when the segment route cannot originate at
all (no SRv6 locator — the origination gate in
`compute_mup_segment_desired`, `bgp/route.rs:14643`).

The **strict variant** remains implementable on top of the same stages, and
the choice affects only the *selection input*, not the Stage 2/4 mechanics
(the `GTP_PDR` key change and the `(vrf_id, nh)` NHT re-key are identical
under either semantics):

* resolve only against ISD/DSD routes present in the holding VRF's
  `local_rib` — the exact source `reconcile_mup_st1_isd` /
  `reconcile_mup_st2_dsd` already use (`bgp/vrf/inst.rs:883/1003`);
* use the catalog only to map a **locally-originated** segment route's RD to
  its origin VRF's kernel table (the RD → origin-VRF rule of
  `mup_apply_selected`, PR #1691);
* costs: the collocated case must configure `mup route-target import`
  cross-links (N6 imports the ISD's RT, N3 imports the DSD's RT), and
  GTP-only boxes need **SID-less segment origination** — which would promote
  that item out of Stage 6 into a Stage 3 prerequisite.

Default if unchallenged at review: ship the catalog semantics (Stages 3–4 as
written), keep the strict variant as a documented tightening option.

### 3.2 VRF-scoped GTP-U match (cradle + seam)

* `GtpPdrKey` (`cradle-common/src/lib.rs:484`) gains the match context:
  `{ vrf_id: u32, dst: [u8;4], teid: [u8;4] }` (0 = global).
* `try_gtp_xdp` keys the lookup with the **ingress port's VRF** (`PORTS` map
  by `ctx.ingress_ifindex()`; ports already carry `vrf_id`, `main.rs:479`).
  A G-PDU arriving on a VRF-bound port only matches PDRs installed for that
  VRF; global-port arrivals only match `vrf_id 0` entries.
* Proto (`proto/cradle.proto`, mirrored in zebra-rs `proto/cradle.proto`):
  `GtpPdr` gains `uint32 match_vrf = 4;`, `GtpPdrDel` gains
  `uint32 match_vrf = 3;` (proto3 default 0 = global — an old zebra client
  keeps working against a new cradle).
* Seam pass-through: `dataplane.rs gtp_pdr_add/del`, zebra
  `Message::CradleGtpPdrAdd/Del` (`rib/inst.rs:415/3769`),
  `fib/netlink/handle.rs:703`.

Zebra-side rule (stage 3): `match_vrf = own table` when the ST2-holding VRF
is `segment interwork`, else `0`. This also fixes the cross-VRF key
collision/stomp for scoped VRFs.

Behavior note: after the cradle half ships, PDRs stop matching on VRF-bound
ports until zebra sends `match_vrf` — that combination is today's *broken*
invariant-violating case (the port VRF clobbers the decap target), never a
supported topology, so the tightening is acceptable and documented.

### 3.3 Decap target from the Direct-segment id (zebra)

`reconcile_mup_gtp_uplink` (`bgp/vrf/inst.rs:1089`): for each selected ST2,
`pdr.vrf_id` (the inner-lookup table) becomes

1. the table of the **direct segment whose `mup-ext-comm` equals the ST2's
   MUP-EC** (via the catalog; the ST2-side EC is already read by
   `mup_direct_segment_id(&rib.attr)` exactly as `reconcile_mup_st2_dsd`
   does, `bgp/vrf/inst.rs:1018`), else
2. the holding VRF's own table (today's behavior).

The install diff base widens from `(dst, teid)` to
`(match_vrf, dst, teid) → inner_table`.

### 3.4 Outer context from the interwork prefix + VRF-scoped NHT (zebra + rib)

`reconcile_mup_gtp_downlink` / the endpoint NHT: the ST1's gNB endpoint is
resolved in

1. the table of the **most-specific interwork segment prefix containing the
   endpoint** (catalog; same containment rule as `reconcile_mup_st1_isd`,
   `bgp/vrf/inst.rs:927-944`), else
2. table 0 (today's behavior).

`mup_endpoint_track_cache` (`bgp/route.rs:3334`) takes the resolved table id
instead of the literal `vrf_id: 0`. Of the two plumbing gaps flagged at
design time, implementation found only one real:

* **RIB re-notify** — *already closed upstream*: the four
  `*_route_{add,del}_vrf` paths end with `nht_recompute_and_notify()`
  (added by the PIM RPF-in-VRF work), so VRF-table route changes re-fire
  watchers today; registration + resolution were already per-VRF (entries
  keyed `(vrf_id, nh)`, `nht_resolve(vrf_id, nh)`). The one genuinely
  missing recompute — dropping a whole VRF table on `VrfDel` — is added.
* **Update identity** — real: `RibRx::NexthopUpdate` carried no `vrf_id`,
  and BGP's `NexthopCache.entries` was keyed by bare `IpAddr`, so the same
  address tracked in two tables would collide. Fixed: `vrf_id` on
  `NexthopUpdate`, BGP cache keyed `(vrf_id, IpAddr)`, every existing user
  mechanically at `(0, nh)`; PIM binds and ignores the field (global-only
  registrations).

Implementation refinement: the endpoint-table choice lives on the
`NexthopCache` itself as a mirrored interwork-prefix view
(`set_mup_interwork`, fed by `push_mup_segment_catalog`) rather than
threading the catalog through every `BgpTop` construction; on a catalog
change, live `MupEndpoint` registrations are **migrated** to their new
table (untrack/unregister old, retrack/register new; an already-live
target entry re-dispatches the ST1 with its current resolution since no
sync-reply fires).

Cradle needs **no downlink change** — it never looks up the outer packet;
zebra keeps handing it a fully resolved `(gw, oif)`.

### 3.5 Decap-metadata precedence (cradle, standalone fix)

At the TC FIB stage the ingress port's VRF currently overrides the decap
metadata (`let vrf_id = if port_vrf != 0 { port_vrf } else { tc_meta_vrf }`,
`main.rs:1835-1838` and v6 twin `:2026-2029`). Flip the precedence: metadata
— set only by an explicit decap stage (GTP PDR, seg6 `pop_decap_local`,
MPLS pop) that *knows* the inner table — wins; the port binding describes the
**outer** context. Non-decapped packets carry no metadata, so plain VRF
routing is unchanged. This is a latent-bug fix independent of MUP (the same
hazard exists for an SRv6 End.DT decap on a VRF-bound underlay port) and is
what actually allows an N3 port to live in a VRF.

Implementation checkpoint: confirm `tc_meta_vrf`'s magic-cookie check cleanly
disambiguates the L3 meaning from the L2 meta reuses (attachment-circuit
ifindex `main.rs:1599`, xconnect nexthop id `main.rs:1615`) before flipping.

## 4. Stages

Each stage is one PR (zebra-rs and cradle-rs PRs counted separately), lands
green on its own, and never breaks the single-N6 shape. Compat gate for every
zebra stage: `@bgp_mup_*` BDD suite + cradle `@cradle_mup_gtp_single_n6` /
`@cradle_mup_gtp_zebra` unchanged.

### Stage 1 — cradle: decap metadata wins over port VRF

*cradle-rs only; smallest, self-contained bugfix (§3.5).*

* `l3_forward_v4/v6`: `vrf_id = tc_meta_vrf != 0 ? tc_meta_vrf : port_vrf`.
* BDD: seg6/GTP decap arriving on a VRF-bound port forwards in the decap's
  table; plain (non-decap) traffic on the same port still uses the port VRF.
* Removes the datapath half of the "N3 must stay in VRF 0" invariant.

### Stage 2 — cradle + seam: VRF-scoped `GTP_PDR`

*cradle-rs first (proto default keeps the old zebra client working), then the
zebra-rs proto mirror + pass-through sending `match_vrf = 0` (behavior-
preserving).*

* §3.2 in full: key struct, `try_gtp_xdp` ingress-port scoping, proto fields,
  `dataplane.rs`, zebra `CradleGtpPdrAdd/Del` + fib handle signatures.
* cradle BDD: a PDR installed for VRF *N* matches only on VRF-*N* ports; a
  `vrf 0` PDR only on global ports; same `(dst, teid)` under two VRFs
  coexist and delete independently.

### Stage 3 — zebra: segment catalog + faithful uplink

* `MupSegmentCatalog` (§3.1): global recompute + diff-gated push;
  per-VRF field, re-reconcile on receipt.
* Uplink resolution (§3.3): `match_vrf` from interwork membership, decap
  target from the Direct-segment id, catalog fallbacks.
* Tests: catalog-resolution units (ext-comm hit / miss / no-EC; interwork vs
  plain holding VRF); reconciler-emission units (mirroring
  `mup_dual_origination_tests`); single-N6 BDD unchanged.

### Stage 4 — rib + zebra: VRF-scoped endpoint NHT + faithful downlink

* RIB: re-notify on VRF-table changes; `NexthopUpdate.vrf_id`; BGP
  `NexthopCache` keyed `(vrf_id, nh)` (§3.4 — mechanical `(0, nh)` migration
  for all existing users, one PR-wide sweep).
* Downlink resolution: endpoint → covering interwork prefix → that VRF's
  table for `NexthopRegister` and re-dispatch (`mup_redispatch_endpoint`,
  `nht_reeval_dep` arm `bgp/inst.rs:5008`); fallback 0.
* Tests: NHT units for `(vrf, nh)` identity; downlink reconciler units;
  single-N6 BDD unchanged.

### Stage 5 — labs, BDD, book

* cradle BDD `@cradle_mup_gtp_n3_vrf`: the faithful two-VRF UPF with the N3
  port **inside a kernel VRF**, round-trip ICMP + counters (the topology that
  is impossible today). *As implemented:* free5GC-shaped session via
  pfcp-inject (PFCP on loopback), dual-segment origination asserted per RD
  (`[ST1]` under N6's, `[ST2]`+`mup:1:6` under N3's), round trip through
  both re-scoped lookups.
* zebra: the §2 target configuration is proven end-to-end **by that BDD**;
  `bdd/mup-lab` gains a variant README section pointing at it and at the
  book, rather than a parallel config file — this lab's `mun3` doubles as
  the N4 link, so moving it into VRF N3 first needs a dedicated global-table
  N4 veth (the PFCP socket is not VRF-aware), and an unrunnable yaml in the
  lab dir would only drift.
* Book ch-02-35: an "architecture mapping" section — the §1 resolution table,
  both shapes (single-N6 degenerate + faithful N3/N6), the N4 note, and
  retiring the "N3 stays in the global table" invariant notes (Stage 1/2
  turned it from a correctness requirement into a mere default).

### Stage 6 — the deferred knobs (implemented)

* **`lookup-network-instance`** — *as implemented, generalized*: the leaf
  lives on the `segment interwork` entry and names the segment's **GTP-side
  routing context** when it is not the declaring VRF itself. The catalog's
  interwork entry carries the named VRF's kernel table (entry gated on that
  table being known); the uplink match context and the downlink endpoint
  resolution both consume it, so the split shape needs no per-rule special
  cases. The flagship use is the **GTP-gateway variant**: ONE service VRF
  binds both `route` directions (the single-N6 shape) while its interwork
  declaration names a bare kernel VRF as N3 — no `router bgp vrf` block on
  the named VRF at all. Proven end-to-end by `@cradle_mup_gtp_lookup_ni`.
  The only new grammar in the whole plan.
* **SID-less segment origination** — *implemented*: a `dataplane gtp` VRF
  without `encapsulation srv6` originates its DSD/ISD with no SRv6 L3
  Service Prefix-SID; the export stamps the `mup-c` `controller-address` as
  the next-hop (gated on it being configured — there is no locator to
  derive one from). `MupSegmentDesired.sid` became `Option`; the SRv6 path
  is untouched. Proven by the `bgp_mup_sidless_segment` BDD (originate +
  receive, `should not contain` SID assertions).
* **N9 / SRGW composite** — *implemented, zebra-only*: `reconcile_mup_gtp`
  composes with the existing SRv6 machinery. Downlink: an ST1 whose gNB
  endpoint is covered by a received ISD (usable SID + resolved transport)
  — and not by the local catalog — steers via `reconcile_mup_st1_isd`
  (now filterable) instead of local GTP; precedence is local catalog →
  remote ISD → fallback GTP. Uplink: an ST2 whose Direct-segment id
  resolves to a received DSD (and no local direct segment) installs
  default v4+v6 H.Encaps routes in the VRF table, steering GTP-decapped
  traffic to the anchor (the PDR decap is unchanged). **N9 between GTP
  peers is emergent**: a SID-less remote segment produces no SRv6 steer,
  so the GTP outer resolves by ordinary FIB toward the peer — exactly the
  fallback path. Proven by `bgp_mup_srgw_gtp`.
* **GTP6** (v6 outer) — *implemented*: cradle gains `GTP_PDR6` /
  `GTP6_ENCAP` (`H.M.GTP6.D` / `GTP6.E`, `NH_F_GTP6`, a bpf-to-bpf decap
  frame to stay under the 512-byte combined-stack ceiling), the zebra
  seam is family-wide (`IpAddr`/`IpNet` end to end), and the reconcilers
  accept either same-family tunnel pair with any-family UE prefix. The
  outer UDP checksum is 0 (RFC 6935/6936 zero-checksum tunnel mode —
  cradle's decap never validates it; non-cradle peers need zero-checksum
  acceptance). Proven by `@cradle_gtp6` and `@cradle_mup_gtp6_zebra`.

## 5. Compatibility summary

| Config | Today | After Stage 5 |
|---|---|---|
| Single-N6 (`mobile` binds st1+st2, no segments, N3 port global) | works | identical behavior via the §2 defaults |
| Two-VRF split (`mobile-dl`/`mobile-ul`, N3 global) | works | identical (each holding VRF is its own decap target; no interwork membership → match_vrf 0, outer table 0) |
| Faithful N3/N6 (§2), N3 port in a kernel VRF | **broken** (three blockers, §1) | works; the architecture shapes are the config |
| Same `(endpoint, TEID)` in two scoped VRFs | silent collision | independent entries |
