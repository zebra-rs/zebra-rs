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

## Status (2026-06-24) — DESIGN ONLY, not started

Nothing here is implemented yet. What the tree **already has** (so phases
build on it, not from scratch):

| Building block | State | Where |
| -------------- | ----- | ----- |
| `EvpnRouteType::EthernetAd` (1), `EthernetSr` (4) | **enum stub only** — fall through to the parse error arm; no struct / `EvpnPrefix` variant / emit | `nlri_evpn.rs` |
| ESI as opaque `[u8;10]` + `esi_display()` | **done**; no ESI-Type (0–5) modelling | `nlri_evpn.rs`; `BgpRib.esi: Option<[u8;10]>` in `route.rs` |
| **ES-Import RT** EC (`0x06`/`0x02`, auto-derived from `esi[1..7]`) | **done** — `es_import_rt()` / `as_es_import_rt()`; today only attached to Type-7/8 | `ext_com.rs` |
| **DF Election EC** (`0x06`/`0x06`, RFC 8584) | **done** — `DfElectionEc`, `ALG_DEFAULT`=0 / `ALG_HRW`=1, AC-DF bit | `ext_com.rs` |
| **ESI Label EC** (`0x06`/`0x01`, RFC 7432 §7.5) | **MISSING** — Phase 1 adds it | — |
| EVPN import-RT filtering | **MISSING** — EVPN routes store globally; no per-RT import gate (Phase 3 adds it) | `route.rs::route_evpn_update` |
| `evpn ethernet-segment` / per-interface ESI config | **MISSING** — config is VNI-scoped (`advertise-all-vni`), not ES-scoped | `zebra-bgp-evpn.yang`, `config.rs` |
| Origination pattern (`evpn_originate_*` + `BgpTop` builder), generic advertise (`route_advertise_evpn_to_peers`), receive (`route_evpn_update`) | **done** — Type-4/1 origination + import slot into these | `route.rs` |

| Phase | Slice | State |
| ----- | ----- | ----- |
| 0 | Design doc (this file) | **this PR** |
| 1 | Codec — Type 1 + Type 4 NLRI, ESI Label EC, `Esi` typing | planned |
| 2 | ESI configuration (`evpn ethernet-segment`) | planned |
| 3 | ES discovery — Type-4 origination/import + import-RT filtering | planned |
| 4 | DF election (service-carving; HRW sub-phase) | planned |
| 5 | Type 1 A-D — per-ES + per-EVI, fast-convergence withdraw | planned |
| 6 | Data plane — DF-gated BUM, split-horizon, aliasing | planned (hardest; likely its own plan) |
| — | RFC 9251 synch dataplane (Type 7/8 organic) | unblocked by 1–5, separate |

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

**Phase 1 — Codec.** Type 1 (`EvpnEthernetAd`) and Type 4
(`EvpnEthernetSeg`) structs + `EvpnRoute` + `EvpnPrefix` variants +
parse/emit + `Display` + round-trip tests, in `nlri_evpn.rs` (mirror the
Type-6/7/8 work). Add the **ESI Label EC** to `ext_com.rs` (constructor +
`is_/as_` accessor + Display + single-active flag). Introduce an `Esi`
newtype over `[u8;10]` with type-aware construction/Display (Type-0 parse
from CLI, reserved-value checks) — used by config and the new routes.
*Self-contained, fully unit-testable; no behaviour change.*

**Phase 2 — ESI configuration.** `evpn ethernet-segment <name>` with `esi
<type-0 value>` and `redundancy-mode {all-active|single-active}`, bound to
an access interface (new YANG under `zebra-bgp-evpn.yang` + handlers in
`config.rs`). A per-ES state struct (`EthernetSegment { esi, mode, df_state,
peers }`) on `Bgp`. Auto-derive the ES-Import RT. No routes yet — just the
config surface and state.

**Phase 3 — ES discovery + import-RT filtering.** Originate the **Type-4**
(ES-Import RT + DF Election EC; reuse the `evpn_originate_*` + `BgpTop`
pattern). Add **EVPN import-RT filtering** to `route_evpn_update`: import a
Type-4 only when its ES-Import RT matches a locally-configured ES, and
build the per-ES PE membership set. **Gotcha:** `route_rts_from_ecom`
matches `low_type == 0x02` regardless of high-type — the ES-Import RT
(`0x06/0x02`) must be disambiguated by high-type so it isn't mistaken for a
standard RT. (This filtering also lets the already-shipped Type-7/8
ES-Import RT scope actually take effect — closes that follow-up.)

**Phase 4 — DF election.** Service-carving (§8.5) over the membership set,
per `(ES, VNI)`: a hold timer (default 3 s, re-armed on membership change),
ordered PE-IP list, `V mod N` ⇒ DF. Per-ES `df_state` + `show evpn
ethernet-segment`. RFC 8584 **default-vs-HRW** negotiation via the
`DfElectionEc` (lowest common algorithm); HRW itself an optional sub-phase.
Still control-plane: DF state is computed and shown, not yet enforced.

**Phase 5 — Type 1 A-D routes.** Originate the **per-ES A-D** (MAX-ET + ESI
Label EC carrying the single-active flag) and, per EVI, the **per-EVI
A-D**. **Mass-withdraw** the per-ES A-D on ES/link-down so remote PEs
reroute in one update (RFC 7432 fast convergence). Import + store the peers'
A-D routes (feeds Phase 6 aliasing).

**Phase 6 — Data plane (hardest; likely its own multi-PR plan).**
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
- **BDD:** a `@bgp_evpn_ethernet_segment` feature — two PEs (z1/z2) on a
  shared ES (manual Type-0 ESI), assert Type-4 exchange, DF election outcome
  (`show evpn ethernet-segment`), and per-ES/per-EVI A-D presence. Data-plane
  assertions (DF-gated flood, aliasing) gate on the Phase-6 mechanism and a
  dual-homed-CE topology. End every feature with an explicit teardown.
- **Interop:** spot-check Type-1/4 + DF against FRR before the data plane.
