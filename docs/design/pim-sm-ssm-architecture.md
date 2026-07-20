# PIM-SM/SSM — Status, Remaining Work & Non-Goals

**Status: implemented and merged.** The PIM Sparse-Mode / SSM arc is complete for both
address families.

- **IPv4** — Phases 1–8: packet codec, engine skeleton (Hello/neighbors/DR election),
  IGMPv2/v3, kernel dataplane + SSM, ASM with static RP (Register / Register-Stop / KAT /
  SPT switchover / (S,G,rpt) prune), Assert + LAN behaviors, per-VRF instances, and BSR
  (RFC 5059).
- **IPv6 / MLD** — Phases 0–9: adjacency over link-local, MLDv1/v2, the `Mrt6` datapath +
  SSM, ASM + Register, Assert, per-VRF, BSR with the RFC 2362 group-to-RP hash, and
  Embedded-RP (RFC 3956). Full v4↔v6 feature parity.
- **Cross-cutting** — the `router pim tracing` subtree (PR #2019) and the explicit
  interface `enabled` activation flag (PR #2031, OSPF/IS-IS style).

Each phase is proven by a live BDD feature under `bdd/tests/features/pim*.feature`
(16 features across both families). The operational surface is documented in the PIM book
chapter (`book/src/ch-17-00-pim.md`); the IPv6-specific design lives in
`pim-ipv6-architecture.md`.

This document now tracks only what remains, what is explicitly out of scope, and the open
questions still to settle.

---

## Remaining tasks

| Task | Notes |
|---|---|
| (S,G,rpt) divergence BDD | The SGrpt prune path (SPT diverging from the RPT) is implemented and unit-covered but has no dedicated live BDD scenario. Add one when a topology where the SPT and RPT genuinely diverge exists. |
| Per-VRF BSR configuration | C-BSR / C-RP configuration is currently default-table only (both address families). Extend BSR config to VRF instances. |
| BSR RP-set fragmentation | The RP-set is flooded and applied as a whole. Implement fragment handling for RP-sets too large for a single Bootstrap message. |
| KAT signal / `show mroute` counters | (S,G) keepalive and forwarding counters are read on demand at show time via `/proc` today. Add a periodic `SIOCGETSGCNT` poller only if keepalive accuracy proves to need one. |
| SPT-switchover policy surface | Only `immediate` / `never` is exposed. Packet/byte-threshold switchover policies can be added if requested. |

---

## Deferred / non-goals (explicit)

| Item | Why |
|---|---|
| MSDP / Anycast-RP | Inter-domain ASM (TCP peering, SA caches) — its own arc. |
| AutoRP | Cisco-proprietary; BSR is the standards-track mechanism and is implemented. |
| PIM-DM / State-Refresh | Different protocol personality; SM/SSM covers the target deployments. |
| BFD for PIM neighbors | The house BFD-client pattern exists; can be bolted on later. |
| MLAG / VxLAN BUM / EVPN coupling | Interacts with the cradle/EVPN work; revisit after this core. |
| mtrace, ssmpingd, IGMP proxy | Diagnostics / edge features. |
| ECMP rebalance, MRIB lookup modes | Need multicast-table (MRIB) support zebra-rs does not have. |
| BSR scoped-zone awareness | Admin-scoped multicast zones; not built (see `pim-ipv6-architecture.md`). |

The original plan also listed **IPv6 PIM + MLD** as deferred; it has since been delivered
in full and is no longer a non-goal.

---

## Open questions

Of the questions the plan left open, two remain — both captured as Remaining tasks above:

- **`show mroute` counters / KAT signal** — on-demand `/proc` read at show time vs. a
  periodic `SIOCGETSGCNT` stat poller. Currently on-demand; revisit only if keepalive
  accuracy demands a poller.
- **SPT-switchover policy** — `immediate` / `never` today; finer packet/byte-threshold
  policies deferred until requested.

The other two are settled: interface activation resolved to the explicit `enabled` boolean
(PR #2031), and IGMP/MLD query TX uses a dedicated per-interface socket path.
