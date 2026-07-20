# IPv6 PIM-SM/SSM and MLD — Status, Remaining Work & Non-Goals

**Status: implemented and merged.** IPv6 PIM Sparse-Mode / SSM and MLD are delivered as a
first-class address family, sharing one compile-time-generic protocol core with IPv4:
a single `Pim<A: PimAf>` actor (and `Gm<A>` membership engine, `PimForwardingPlane<A>`
forwarding plane) monomorphized per `(VRF, AF)` instance. No IPv4 module is duplicated,
and the TIB stays family-typed rather than an unvalidated `IpAddr` table.

Phases 0–9 all landed:

- **Phase 0** — IPv4 correctness floor: DR gating with the `pim_assert` rework, GenID
  re-sync toward a bounced neighbor, neighbor secondary-address storage/matching, and ABI
  layout tests for the existing structs.
- **Phase 1** — codec groundwork: explicit `PimChecksumContext`, MLD wire types,
  exponent-coded Max-Resp/QQIC, mixed-family rejection, shared ICMPv6 checksum helper.
- **Phase 2** — genericization of the engine, membership and forwarding plane to
  `A: PimAf`; IPv4 runtime byte-identical.
- **Phase 3** — the shared `Gm<A>` membership engine; PIMv6 adjacency, neighbor and DR
  election over link-local transport.
- **Phase 4** — MLDv1/v2 querier and membership via `Gm<Ipv6>`.
- **Phase 5** — the `Mrt6` MIF/MFC forwarding plane and SSM: MLDv2 `(S,G)` report →
  PIMv6 Join → kernel MRT6 → real UDPv6 delivery.
- **Phase 6** — static-RP ASM and the IPv6 Register path.
- **Phase 7** — IPv6 Assert and per-VRF `Pim<Ipv6>`.
- **Phase 8** — IPv6 BSR (RFC 5059) with the RFC 2362 group-to-RP hash.
- **Phase 9** — Embedded-RP (RFC 3956).

Plus the interface `enabled` activation flag (PR #2031), shared with IPv4: PIMv6/MLD
activate only on explicit config (`router pim ipv6 interface <if> enabled true`, and
`mld enabled true` for membership); an IPv6 address alone never starts multicast routing.

Each phase is proven by a live BDD feature (`bdd/tests/features/pim6_*.feature`). The
operational surface is documented in the PIM book chapter (`book/src/ch-17-00-pim.md`);
the shared IPv4 status lives in `pim-sm-ssm-architecture.md`.

This document now tracks only what remains, what is explicitly out of scope, and the open
questions still to settle.

---

## Remaining tasks

| Task | Notes |
|---|---|
| Third-party interoperability | BDD coverage is self-interop over veth pairs. Validate PIMv6 adjacency, MLDv2-driven SSM and BSR against an external PIMv6/MLD implementation. |
| BSR scoped-zone awareness | IPv6 BSR does not yet honor admin-scope boundaries — at minimum it should refuse to elect/flood across `ff02`-scope zones. |
| Per-VRF BSR configuration | C-BSR / C-RP configuration is currently default-table only (both address families). |
| BSR RP-set fragmentation | The RP-set is flooded and applied as a whole; add fragment handling for RP-sets too large for a single Bootstrap message. |
| KAT signal / MFC counter polling | Receiverless `(S,G)` entries churn on the 210 s keepalive. A `SIOCGETSGCNT[_IN6]` poller is a both-families-or-neither decision — currently neither (on-demand `/proc` read at show time). |

---

## Deferred / non-goals (explicit)

| Item | Why |
|---|---|
| MSDP / Anycast-RP | Inter-domain ASM (TCP peering, SA caches) — its own arc. |
| AutoRP | Cisco-proprietary; BSR is the standards-track mechanism and is implemented. |
| PIM-DM / State Refresh | Different protocol personality; SM/SSM covers the target deployments. |
| BFD for PIM neighbors | The house BFD-client pattern exists; can be bolted on later. |
| mtrace, MLD proxy | Diagnostics / edge features. |
| MLAG / VXLAN multicast coupling | Interacts with the cradle/EVPN work; revisit after this core. |
| Multicast ECMP rebalance | Needs multicast-table (MRIB) support zebra-rs does not have. |

---

## Open questions

Two shared decisions remain open — both captured as Remaining tasks above and mirrored in
`pim-sm-ssm-architecture.md`:

- **MFC counter polling / KAT signal** — on-demand `/proc` read at show time vs. a
  periodic `SIOCGETSGCNT[_IN6]` poller. Must be resolved for both families together;
  currently on-demand only.
- **SPT-switchover policy** — `immediate` / `never` today; finer packet/byte-threshold
  policies deferred until requested.

Every other design question the original plan raised — checksum context, link-local
scoping, secondary-address upstream matching, MRT6 upcall discrimination, and
supervisor/show routing — is settled by the shipped implementation.
