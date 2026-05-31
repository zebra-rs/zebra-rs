# OSPF Flex-Algorithm (RFC 9350) — Implementation Recap

Status: **complete (2026-05-31).** Both OSPFv2 and OSPFv3 forward
SR-MPLS under a Flexible Algorithm end-to-end — a router advertises its
participation, definitions, per-link affinity, and per-algo Prefix-SIDs;
peers run a per-algo FAD-filtered SPF, build a per-algo RIB, and install
the per-algo Prefix-SID labels into the kernel MPLS LFIB.

This memo is the at-a-glance summary for the OSPF side. The IS-IS
reference implementation (which this work mirrors) is recapped in
[`flex-algo-roadmap.md`](flex-algo-roadmap.md).

## What it does

Flexible Algorithm (RFC 9350) lets operators define constraint-based
topologies (algorithms 128..255) and forward over them with SR-MPLS. Each
algorithm carries a FAD (Flex-Algorithm Definition): a metric-type, a
priority, admin-group include/exclude constraints (RFC 7308 Extended
Admin Group), and an exclude-SRLG list. A router computes a separate SPF
per algorithm over the links that pass that algorithm's constraints, then
forwards using per-algorithm Prefix-SID labels.

Configuration lives under `router ospf` / `router ospfv3`:

- `flex-algo <128..255>` — per-algo definition (`advertise-definition`,
  `metric-type`, `priority`, `prefix-metric`, `affinity {include-any,
  include-all, exclude-any}`, `srlg-exclude`, `dataplane`, `fast-reroute`).
- per-interface `affinity <name>` — the link's admin-group names.
- per-interface `flex-algo-prefix-sid <algo> {index|absolute}` — the
  per-algo Prefix-SID for that interface's prefix.

The affinity-name → bit-position table (`/affinity-map`) and the SRLG
table (`/srlg`) are **global** (shared by IS-IS / OSPFv2 / OSPFv3); config
is broadcast to every IGP task, each keeping its own copy.

## Shared core

The protocol-neutral pieces live outside `ospf/` so IS-IS and both OSPF
versions share them:

- `crate::flex_algo` — `FlexAlgoConfig` (staging + commit), `FlexAlgoEntry`,
  `FadMetricType`, `AffinityMap`, `SrlgGroupBuilder`, `sr_algorithms()`,
  `link_passes_fad()`, `local_link_affinity()`, the `AffinityBits` trait.
- `packet_utils::{Algo, ExtAdminGroup, SidLabelTlv}` — wire types shared
  by `isis-packet` and `ospf-packet`.

`Ospf<V>` (generic over `Ospfv2`/`Ospfv3`) holds the per-instance fields:
`flex_algo`, `affinity_map`, `srlg_config`/`srlg_groups`, `spf_flex_algo`,
`rib_flex_algo` (v2 IPv4), `rib6_flex_algo` (v3 IPv6). The
`flex_algo_table_exec` / `commit_flex_algo_tables` helpers are `impl<V>`
and shared by both versions.

## Codepoints

| Object | OSPFv2 | OSPFv3 |
|--------|--------|--------|
| FAD TLV | RI Opaque LSA, type 16 | E-Router-LSA, top-level TLV 16 |
| ASLA sub-TLV | Ext-Link Opaque LSA, sub-TLV 10 | Router-Link TLV, sub-TLV 11 |
| Extended Admin Group | sub-sub-TLV 20 | sub-sub-TLV 21 |
| SR-Algorithm | RI Opaque LSA, type 8 | E-Router-LSA SR-info |
| Per-algo Prefix-SID | Ext-Prefix Opaque LSA | E-Intra-Area-Prefix-LSA |
| SABM Flex-Algo X-bit | `0x10` | `0x10` |

The SABM/UDABM length must be 0/4/8 octets in OSPF (RFC 9492), unlike
IS-IS's 1-octet form. The OSPFv2 FAD/ASLA ride **separate** Opaque LSAs;
the OSPFv3 FAD rides the per-router SR-info E-Router-LSA and the ASLA
rides each per-link E-Router-LSA Router-Link TLV (so the per-algo SPF
joins affinity to a Router-LSA link by `(adv_router, interface_id)`,
whereas v2 keys the join by `(adv_router, link_id, link_data)`).

## OSPFv3 SR baseline caveat

zebra-rs's OSPFv3 SR-MPLS uses a **non-standard** baseline: SR
capabilities (SR-Algorithm, SRGB, SRLB) and the FAD ride an E-Router-LSA
at a reserved Link State ID (`SR_INFO_LSID`) rather than the RFC 8666
Router Information arrangement. The flex-algo work was layered on this
existing baseline (per an explicit decision), so OSPFv3 flex-algo interop
with other vendors is not expected without aligning the SR baseline
first. OSPFv2 follows the standard RI/Ext-Link/Ext-Prefix Opaque LSAs.

## Phase-by-phase (all merged)

### OSPFv2 — #1081–#1098

| PR | What landed |
|---:|---|
| #1081 | Shared `crate::flex_algo` core; `ExtAdminGroup` → `packet-utils` |
| #1082 | OSPFv2 FAD TLV codec (RI LSA type 16) |
| #1084 | OSPFv2 ASLA + Ext Admin Group codec (Ext-Link, RFC 9492) |
| #1086 | Global `/affinity-map` + `/srlg` (hard cutover off `router isis`) |
| #1089 | `FlexAlgoConfig` → `crate::flex_algo::config` (path-parameterized) |
| #1090 | `Ospf<V>` flex-algo fields + v2 config dispatch + YANG |
| #1091 | Per-interface affinity (`LinkConfig.affinity`) |
| #1092 | SR-Algorithm TLV advertises configured algos |
| #1093 | FAD TLV origination (`build_fad`) |
| #1094 | Per-link ASLA on Ext-Link LSA (`build_link_asla`) |
| #1096 | Per-algo Prefix-SID origination (Ext-Prefix LSA) |
| #1095 | Per-algo SPF compute + `show ip ospf flex-algo` |
| #1097 | Per-algo IPv4 RIB (in-memory) |
| #1098 | Per-algo Prefix-SID kernel MPLS-ILM install |

### OSPFv3 — #1099–#1106

| PR | What landed |
|---:|---|
| #1099 | OSPFv3 FAD + ASLA codec (`v3.rs`) |
| #1100 | OSPFv3 config dispatch + YANG |
| #1101 | SR-Algorithm participation + FAD origination (`build_fad_v3`) |
| #1102 | Per-link ASLA origination (`build_link_asla_v3`) |
| #1103 | Per-algo Prefix-SID origination (E-Intra-Area-Prefix-LSA) |
| #1104 | Per-algo SPF compute (`graph_v3_flex_algo`) + `show ipv6 ospf flex-algo` |
| #1105 | Per-algo IPv6 RIB (`build_rib6_from_flex_algo`, `rib6_flex_algo`) |
| #1106 | Per-algo Prefix-SID `ilm6` kernel install |

## Deferred (mirrors the IS-IS / OSPFv2 baseline; none blocking)

- **FAPM codec** — Flex-Algorithm Prefix Metric sub-TLV (OSPFv2 Ext-Prefix
  type 3 / OSPFv3 sub-TLV 26). The M-flag is honored in the FAD but the
  per-prefix metric is not yet carried.
- **Multi-router FAD election** — the local FAD config drives constraints;
  there is no winning-FAD election across advertisers (RFC 9350 §5.x).
- **Metric-type** — IGP metric only in SPF; min-unidirectional-link-delay
  and TE-default are carried on the wire but not used for path selection.
- **SRLG enforcement** — `exclude-srlg` is advertised but not enforced in
  the per-algo SPF.
- **Per-algo TI-LFA** — no fast-reroute computation per algorithm yet.
- **Per-algo SRv6** — SR-MPLS only; no per-algo SRv6 locator (OSPFv3).
- **Multi-area** — `spf_flex_algo` / `rib*_flex_algo` are a single
  (last-computed-area) snapshot, fine for the common single-area case.
- **Interop validation** — not yet checked against FRR / IOS-XR. (No FRR
  OSPF flex-algo exists to test v2 against; the v3 SR baseline is
  non-standard, so v3 interop needs the SR baseline aligned first.)
