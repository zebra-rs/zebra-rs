# BGP EVPN Ethernet Segment Multihoming (RFC 7432 / RFC 8584) — Design & Phasing Plan

The foundation for EVPN **multihoming**: letting a CE (host, switch, or
LAG) attach to two or more PEs on the same **Ethernet Segment (ES)** and
have the overlay treat them as one. This is the missing prerequisite under
the deferred RFC 9251 Type-7/8 IGMP/MLD Synch *dataplane* — and under
all-active load-balancing (aliasing), redundancy (DF election), and loop
prevention (split-horizon) in their own right.

It adds the two remaining base-EVPN route types — **1 (Ethernet
Auto-Discovery / A-D)** and **4 (Ethernet Segment)** — plus the per-ES
control machinery: ESI configuration, ES discovery, **Designated Forwarder
(DF) election**, and (data-plane) aliasing + split-horizon. Like the prior
EVPN work it is **control-plane-first**: codec → route exchange → DF
election land before the kernel forwarding behaviour.

Read this first if you're touching
`crates/bgp-packet/src/attrs/nlri_evpn.rs`, `ext_com.rs`, the
`bgp::route::evpn_*` origination/receive paths, or
`zebra-rs/yang/zebra-bgp-evpn.yang`.

Branch: `evpn-es-foundation-*` (per-phase).

## Status (2026-07-01) — CONTROL PLANE COMPLETE (Phases 1–5 merged)

The full EVPN-multihoming **control plane** is on `main`: ESI config,
Type-4 ES discovery, DF election (service-carving), and Type-1 per-ES A-D
exchange, all BDD-validated (`@bgp_evpn_es`, 7/7). Only **Phase 6 (kernel
data plane)** remains. What the tree **already has**:

| Building block | State | Where |
| -------------- | ----- | ----- |
| `EvpnRouteType::EthernetAd` (1), `EthernetSeg` (4) | **done** — struct + `EvpnPrefix` variant + parse/emit/Display/round-trip | `nlri_evpn.rs` |
| ESI as opaque `[u8;10]` + `esi_display()` / `esi_from_str()` | **done**; no `Esi` newtype / ESI-Type (0–5) modelling (manual Type-0 only) | `nlri_evpn.rs`; `BgpRib.esi: Option<[u8;10]>` in `route.rs` |
| **ES-Import RT** EC (`0x06`/`0x02`, auto-derived from `esi[1..7]`) | **done** — `es_import_rt()` / `as_es_import_rt()`; attached to Type-4, per-ES A-D, and Type-7/8 | `ext_com.rs` |
| **DF Election EC** (`0x06`/`0x06`, RFC 8584) | **done** — `DfElectionEc`, `ALG_DEFAULT`=0 / `ALG_HRW`=1, AC-DF bit; on Type-4 | `ext_com.rs` |
| **ESI Label EC** (`0x06`/`0x01`, RFC 7432 §7.5) | **done** (P1/P5) — `esi_label()` / `as_esi_label()`, single-active flag; on per-ES A-D | `ext_com.rs` |
| **EVI-RT EC** (`0x06`/`0x0A`–`0x0D`) | **done** (P1) — `evi_rt_from_rt()` / `as_evi_rt()`; Type 3 (IPv6, 20-octet) deferred | `ext_com.rs` |
| `evpn ethernet-segment <name>` config (esi / redundancy-mode / interface) | **done** (P2) — YANG list + handlers; per-ES state on `Bgp` | `zebra-bgp-evpn.yang`, `config.rs`, `ethernet_segment.rs` |
| Type-4 ES origination + membership + DF election | **done** (P3/P4) — `evpn_originate_ethernet_seg`, `es_df_candidates`, `negotiate_df_alg`, `designated_forwarder`; `show bgp evpn ethernet-segment` | `route.rs`, `show.rs` |
| Per-ES Type-1 A-D origination (MAX-ET + ESI Label EC) | **done** (P5) — `evpn_originate_ethernet_ad_es`, combined `evpn_originate/withdraw_es_routes` | `route.rs` |
| EVPN import-RT filtering | **MISSING** — EVPN routes still store globally; membership is derived by scanning the Loc-RIB for the ES-Import RT, not gated on import (deferred) | `route.rs::route_evpn_update` |
| Per-EVI A-D (aliasing) | **MISSING** — needs EVI-to-ES mapping config (deferred, feeds Phase 6) | — |
| DF hold timer (3 s), HRW algorithm | **MISSING** — DF recomputed on membership change, default service-carving only (deferred) | — |

| Phase | Slice | State |
| ----- | ----- | ----- |
| 0 | Design doc (this file) | **done** (#1633) |
| 1 | Codec — Type 1 + Type 4 NLRI, ESI Label + EVI-RT ECs | **done** (#1634) |
| 2 | ESI configuration (`evpn ethernet-segment`) | **done** (#1635) |
| 3 | ES discovery — Type-4 origination + membership | **done** (#1636) |
| 4 | DF election (service-carving; default-vs-HRW negotiation) | **done** (#1638) |
| 5 | Type 1 A-D — **per-ES** + fast-convergence mass-withdraw | **done** (#1702) |
| 6 | Data plane — DF-gated BUM, split-horizon, aliasing | **planned** (hardest; likely its own plan) |
| — | RFC 9251 synch dataplane (Type 7/8 organic) | unblocked by 1–5, separate |

**Deferred from Phases 1–5** (do not re-derive — recorded here): `Esi`
newtype / ESI-Type (0–5) modelling; **EVPN import-RT filtering** (membership
is scanned, not import-gated); **per-EVI A-D** for aliasing (needs
EVI-to-ES mapping); **HRW** DF algorithm (Alg 1); the **3 s DF hold timer**;
**EVI-RT Type 3** (IPv6, 20-octet EC). All feed Phase 6 or are independent
follow-ups.

## RFC surface

| RFC | Role |
| --- | --- |
| RFC 7432 | Base EVPN — ESI (§5), Type-1 A-D (§7.1), Type-4 ES (§7.4), ES-Import RT (§7.6), ESI Label EC (§7.5), DF election (§8.5), split-horizon (§8.3), aliasing/backup (§8.4) |
| RFC 8584 | DF Election framework — capability EC, default vs **HRW** algorithm, AC-DF |
| RFC 8365 | NVO/VXLAN data plane — **local-bias** split-horizon (§8.3.1): VXLAN has no MPLS ESI label, so the source VTEP IP identifies the segment |
| RFC 9251 | Downstream consumer — the Type-7/8 synch dataplane needs an all-active ES + DF |

## Wire formats

### Route Type 1 — Ethernet Auto-Discovery (A-D)

| Field | Len | Notes |
| ----- | --- | ----- |
| RD | 8 | — |
| ESI | 10 | route key |
| Ethernet Tag ID | 4 | route key |
| MPLS Label | 3 | per-path attribute (VXLAN: VNI / 0) |

Route key = **ESI + Ethernet Tag**. Two uses (distinguished by the tag):
- **Per-ES A-D** (§8.2): Ethernet Tag = `MAX-ET` (`0xFFFFFFFF`), NLRI label
  0, carries the **ESI Label EC** (single-active flag + ESI label). Fast
  convergence + split-horizon. *Required.*
- **Per-EVI A-D** (§8.4): Ethernet Tag = the EVI's tag. **Aliasing** /
  backup — a remote PE load-balances a MAC to *every* PE that advertised
  both a per-ES A-D (all-active) **and** a per-EVI A-D for that EVI. *Optional.*

### Route Type 4 — Ethernet Segment

| Field | Len | Notes |
| ----- | --- | ----- |
| RD | 8 | — |
| ESI | 10 | route key |
| IP Address Length | 1 | bits: 32 / 128 |
| Originating Router's IP | 4 / 16 | route key |

Carries the **ES-Import RT** (scopes distribution to PEs on the ES) and the
**DF Election EC**. Drives ES discovery + DF election (§8.5).

### ESI (§5) — 10 octets: `[Type(1)][Value(9)]`

`Type 0` arbitrary (operator-configured 9 octets) · `1` LACP
(sys-MAC + port-key) · `2` MSTP · `3` MAC + 3-octet discriminator · `4`
Router-ID + discriminator · `5` AS + discriminator. Reserved: all-zero =
single-homed, all-`0xFF` = `MAX-ESI`. The **ES-Import RT** auto-derives
from the high-order 6 octets of the 9-octet Value (`esi[1..7]`) — already
how `es_import_rt()` works.

### ESI Label EC (`0x06`/`0x01`, §7.5) — Phase 1 adds this

```
+------+------+--------+----------+-----------------+
| 0x06 | 0x01 | Flags  | Reserved | ESI Label (3)   |
|      |      | (1)    |  (2, =0) | (low 20 bits)   |
+------+------+--------+----------+-----------------+
```
Flags bit 0 (LSB): `0` = **All-Active**, `1` = **Single-Active**. On
per-ES A-D. For VXLAN the label field is unused (local-bias does the
split-horizon); the **flag still matters** (it tells remote PEs the
redundancy mode for aliasing vs backup).

### DF Election EC (`0x06`/`0x06`, RFC 8584) — already coded

`DfElectionEc { df_alg, bitmap }`: `df_alg` 0 = default service-carving,
1 = HRW; `bitmap` carries AC-DF (`0x4000`). On Type-4 to negotiate the
algorithm across the ES.

## Operational model (how the pieces fit)

1. **Configure** an ES on an access port/bridge: an ESI + redundancy mode
   (all-active / single-active). The ES-Import RT auto-derives from the ESI.
2. **Discover peers**: originate a **Type-4** (RD `<router-id>:<auto>`,
   ES-Import RT, DF Election EC). Import received Type-4s **by ES-Import
   RT** → the set of PEs on this ES.
3. **Elect the DF** per `(ES, EVI/VLAN)`: after a hold timer (default 3 s),
   sort the PE IPs, ordinal `i`, DF where `V mod N == i` (service-carving,
   §8.5) — or HRW (RFC 8584) when negotiated. Re-elect on membership change.
4. **Advertise reachability**: a **per-ES A-D** (MAX-ET + ESI Label EC) and,
   per EVI, a **per-EVI A-D**. A link/ES-down **mass-withdraws** the per-ES
   A-D — remote PEs reroute in one update (fast convergence) instead of
   waiting out per-MAC withdrawals.
5. **Forward** (data plane): the **DF** forwards BUM toward the segment;
   non-DF PEs drop it. **Split-horizon** stops a CE's own BUM from looping
   back — VXLAN uses **local-bias** (drop if the ingress VTEP is a known
   peer on the same ES), MPLS uses the ESI label. **Aliasing**: remote PEs
   ECMP unicast across all all-active PEs that advertised the per-ES +
   per-EVI A-D pair.

## Decisions to lock (with Kunihiro) before Phase 1

| Decision | Proposed | Why |
| -------- | -------- | --- |
| **Encapsulation** | **VXLAN first** (RFC 8365), MPLS later | The whole EVPN tree is VXLAN; split-horizon = **local-bias**, not the ESI label |
| **Redundancy mode** | **All-active first**, single-active later | RFC 9251 multihoming needs all-active; it's the common DC case |
| **DF algorithm** | **Default service-carving first**, HRW sub-phase | §8.5 is simplest; HRW (RFC 8584) reuses the existing `DfElectionEc` |
| **ESI type** | **Type 0 (manual) first**, Type 1 (LACP auto) later | No LACP state in zebra-rs yet; manual ESI is deterministic for BDD |
| **Sequencing** | **Control-plane first** (Phases 1–5), data plane (6) last | Mirrors the SMET/Type-7-8 work; the kernel forwarding is the real unknown |

## Phases

**Phase 1 — Codec. ✅ (#1634)** Type 1 (`EvpnEthernetAd`) and Type 4
(`EvpnEthernetSeg`) structs + `EvpnRoute` + `EvpnPrefix` variants +
parse/emit + `Display` + round-trip tests, in `nlri_evpn.rs` (mirrors the
Type-6/7/8 work). Added the **ESI Label EC** and **EVI-RT EC** to
`ext_com.rs` (constructors + `is_/as_` accessors + Display + single-active
flag). *Delta from plan:* the `Esi` newtype was **not** introduced — ESI
stays an opaque `[u8;10]` with the shared `esi_display()` / `esi_from_str()`
helpers (manual Type-0 only; ESI-Type modelling deferred).

**Phase 2 — ESI configuration. ✅ (#1635)** `evpn ethernet-segment <name>`
with `esi <type-0 value>`, `redundancy-mode {all-active|single-active}`,
and `interface` (new YANG list under `zebra-bgp-evpn.yang` + handlers in
`config.rs`). Per-ES state `EthernetSegment { esi, redundancy_mode,
interface }` on `Bgp::ethernet_segments` (`ethernet_segment.rs`);
ES-Import RT auto-derived. Config surface + state only.

**Phase 3 — ES discovery. ✅ (#1636)** Originate the **Type-4** (ES-Import
RT + DF Election EC) via `evpn_originate_ethernet_seg`. *Delta from plan:*
**import-RT filtering was NOT added** — EVPN routes still store globally,
and per-ES membership is derived by **scanning the Loc-RIB** for Type-4s
carrying the matching ES-Import RT (`es_df_candidates`), rather than by an
import gate on `route_evpn_update`. The `route_rts_from_ecom` high-type
disambiguation gotcha therefore remains a Phase-6/follow-up concern, not yet
hit. (Type-7/8 ES-Import RT scoping likewise still un-enforced.)

**Phase 4 — DF election. ✅ (#1638)** Service-carving (§8.5) over the
membership set: ascending PE-IP ordinals, `tag mod N` ⇒ DF
(`designated_forwarder`), with RFC 8584 **default-vs-HRW** negotiation
(`negotiate_df_alg`, lowest common algorithm). `show bgp evpn
ethernet-segment` renders candidates + elected DF. *Delta from plan:* **no
3 s hold timer** (DF recomputed directly on membership change) and **HRW
itself deferred** (any non-zero negotiated alg falls back to carving).
Control-plane only — DF is computed and shown, not enforced.

**Phase 5 — Type 1 A-D routes. ✅ (#1702)** Originate the **per-ES A-D**
(MAX-ET + ESI Label EC carrying the single-active flag; zero VXLAN
local-bias label) via `evpn_originate_ethernet_ad_es`, combined with the
Type-4 in `evpn_originate/withdraw_es_routes`. A single per-ES A-D withdraw
is the RFC 7432 **mass-withdraw**. *Delta from plan:* the **per-EVI A-D was
NOT added** — it needs EVI-to-ES mapping config that doesn't exist yet, so
aliasing (Phase 6) is still blocked on it. Import/storage of peers' A-D
routes rides the generic EVPN Loc-RIB.

**Phase 6 — Data plane (hardest; likely its own multi-PR plan). Planned.**
- **Control-plane prerequisites carried over** (must land first, both
  deferred from earlier phases): the **per-EVI A-D** route (Phase 5 shipped
  only per-ES; aliasing needs the per-ES + per-EVI pair) and — if the DF/
  membership derivation is tightened — **EVPN import-RT filtering** (Phase 3
  left routes stored globally; the `route_rts_from_ecom` high-type gotcha
  bites here).
- **DF-gated BUM**: only the DF floods BUM toward the local segment.
- **Split-horizon (local-bias, RFC 8365 §8.3.1)**: drop overlay BUM whose
  ingress VTEP is a known peer on the same ES (no MPLS ESI label in VXLAN).
- **Aliasing**: ECMP a remote MAC across all all-active PEs that advertised
  the per-ES + per-EVI A-D pair.
- **Open risk:** Linux VXLAN/bridge multihoming primitives are limited;
  local-bias + aliasing may need **eBPF/tc** assists (cf. the RFC 9524
  replication work, `zebra-rs-evpn-rfc9524-replication-plan`). Feasibility
  spike belongs at the top of this phase.

**Then (separate, RFC 9251):** wire the multihomed-ES IGMP/MLD snoop to the
**organic** Type-7/8 origination (`evpn_originate_igmp_*_sync`, today only
the `clear bgp debug …` test command drives them); the DF computes the
combined `(x,G)` across the ES and originates the SMET. This is the payoff
that closes `bgp-evpn-igmp-mld-proxy-followups.md` §6.

## Open questions / risks

- **Data-plane feasibility (biggest unknown).** Does the stock kernel give
  us DF-gated BUM + local-bias split-horizon + aliasing ECMP for VXLAN, or
  do we need eBPF/tc? A Phase-6 spike decides; Phases 1–5 don't depend on it.
- **Import-RT filtering blast radius.** Phase 3 adds the first per-RT import
  gate to the EVPN Loc-RIB; must not regress the "store globally" behaviour
  that Type-2/3/5 rely on (gate only ES-scoped types, or filter additively).
- **FRR interop.** Validate the control plane (Type-1/4 exchange, DF
  election, ES-Import RT) against FRR; full data-plane validation needs a
  real dual-homed-CE topology (two PEs + a LAG/bridge CE), heavier than the
  existing single-VTEP BDDs.
- **ESI source.** Manual Type-0 first; LACP-derived Type-1 needs bond/LACP
  state zebra-rs doesn't track yet.

## Validation

- **Per phase:** `cargo fmt` + workspace clippy + unit tests
  (codec round-trip, EC, DF-election algorithm); smallest-reviewable-PR-first.
- **BDD:** the `@bgp_evpn_es` feature (`bgp_evpn_es.feature`) — two PEs
  (z1/z2) on a shared ES (manual Type-0 ESI) — asserts Type-4 exchange, the
  auto-derived ES-Import RT + DF Election EC, DF election outcome (`show bgp
  evpn ethernet-segment`), per-ES A-D presence (`[1]:[ESI]:[MAX-ET]` +
  `esi-label:all-active:0`), and ES-removal withdraw; ends with an explicit
  teardown. Per-EVI A-D and data-plane assertions (DF-gated flood, aliasing)
  gate on Phase 6 and a dual-homed-CE topology.
- **Interop:** spot-check Type-1/4 + DF against FRR before the data plane.
