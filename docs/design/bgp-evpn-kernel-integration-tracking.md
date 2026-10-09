# EVPN Linux kernel integration — tracking against the feature matrix

Status as of 2026-10-09. Tracks PR #2477 (`ovn-native-evpn`, dual-stack EVPN
through Linux bridge/VXLAN/VRF state) and its follow-up PR #2488
(`evpn-followups`) against the rows of
[`bgp-evpn-support-status.md`](bgp-evpn-support-status.md), plus the
kernel/RIB work the matrix has no row for. Everything here concerns the
**EVPN/VXLAN kernel backend** (no cradle); the SRv6 and MPLS columns are
untouched except where noted.

User guide: [`docs/evpn-kernel-integration.md`](../evpn-kernel-integration.md).
Validation: [`docs/validation/evpn-linux-kernel.md`](../validation/evpn-linux-kernel.md).

## Matrix rows this work changes

| Matrix row (VXLAN column) | Before | Change | PR |
|---|---|---|---|
| **L2 unicast (Type-2 MAC/IP)** | ✅ Kernel via SVD `external`+`vnifilter`; MAC-only (the parser dropped the IP) | Dual-stack MAC/IP: IPv4/IPv6 kept in parse, emit, NLRI keys and ownership; MAC-only and per-IP routes independent; local FDB+ARP/NDP correlated in either order; remote bindings installed as `NOARP` `extern_learn` neighbors. Adopted fixed-VNI VXLAN on flat bridges (not only SVD). Optional Label2 (RFC 7432 §7.2) accepted and re-advertised unchanged, so FRR/EOS symmetric-IRB routes are no longer treated as withdrawn | #2477 |
| **BUM / ingress replication (Type-3)** | ✅ | Originated next hop keeps the selected VTEP (VXLAN `local` / `vtep-source`) instead of the session address, including a VTEP equal to the router-id; routes re-sent when that status changes | #2477 |
| **MAC mobility / aging (RFC 7432 §7.7)** | ✅ (remote vs remote) | Local vs remote decided as FRR's `bgp_path_info_cmp`: sticky, shared ES keeps local, higher sequence, lower VTEP; a remote route that does not win is not installed over the local FDB row, and is installed when the local route goes. Per-IP mobility (FRR neighbor sequence numbers) for an IP moving to another MAC. Sticky/router/default-gateway flags now read from the RFC communities (were read from undefined type `0x09`) | #2488 |
| **L3 / Type-5 IP Prefix (RFC 9136)** | ✅ Symmetric IRB, L3VNI + Router's-MAC EC | Opt-in `kernel-route-exchange`: Type-5 installed through the L3-VNI bridge with RMAC FDB and IPv4 + mapped-IPv6 VTEP neighbors (shared, reference-counted); RMAC shared by several VTEPs re-points to a remaining one; state recovered after link flaps, flushes, VXLAN re-attach, bridge moves and external route deletion. Per-VRF `redistribute kernel` (unicast and blackhole). Limits: IPv4 VTEPs, unicast next hop, configure before sessions | #2477 |
| **Multihoming dataplane** | 🔶 cradle-only by decision; kernel single-homed | No change. The local-vs-remote rule keeps the local path on a shared non-zero ES, consistent with the single-homed kernel backend | — |
| **IPv6 underlay transport** | ✅ Kernel | Bridge Type-5 path supports IPv4 VTEPs only (IPv6 prefixes over an IPv4 VTEP use the mapped gateway) | #2477 (limit) |
| **IGMP/MLD proxy / SMET** | ✅ incl. per-VTEP MDB | No change. The `bgp_evpn_smet` BDD per-VTEP assertion needs iproute2 ≥ 6.5 (see the SMET plan); it fails on 6.1 hosts while the kernel entry is correct | — |
| **ARP suppression** | ❌ Open | **Candidate, unverified.** `neigh_suppress` was already set on VXLAN bridge ports; #2477 now installs remote MAC/IP bindings as neighbors on the bridge, which is what kernel ARP/ND suppression answers from. Needs a namespace check before changing the row | #2477 (prerequisite) |
| **Datapath BDD** | ✅ cradle + kernel playsets | New self-contained Linux namespace test (two zebra-rs speakers, no cradle/FRR/containers): 125 checks incl. kernel-state recovery, crash-and-restart, MAC mobility; root-only kernel tests via `tests/evpn-linux-kernel/run-kernel-tests.sh` | #2477, #2488 |

## Work outside the matrix (RIB / kernel exchange)

| Area | Change | PR |
|---|---|---|
| Kernel route ingestion | IPv6 and VRF kernel routes mirrored; protocol-BGP VRF routes never fed back; kernel echoes of installed routes ignored; NHT resolves through kernel-only underlay routes (not a default) | #2477 |
| Kernel routes per priority | Keyed by (type, priority); blackhole/unicast replacement; IPv4 appended routes kept side by side; IPv6 next-hop deletion removes only that next hop | #2477, #2488 |
| Leftovers from an earlier run | Statics installed as `proto zebra` (`RTPROT_ZEBRA`); startup routes under zebra-rs's protocols (and VRF BGP) enter stale and are replaced or swept after `--leftover-sweep-time`; every leftover priority removed; legacy `proto static` statics adopted on upgrade; blackhole installs replace in place | #2477 |
| SRv6 routes | Never mirrored (fixes OSPF's sweep deleting a live SID); leftovers nothing reinstalled removed at the sweep | #2477, #2488 |
| Shared-IP neighbors | An IP bound to several MACs follows its winning binding | #2477 |
| `lua` build | Test literals fixed for the `lua` CI lane | #2477 |
| Operator logging | Refusal of a peer's route for this node's own MAC logged again (regression from #2477's reconcile path) | #2488 |

## Open items (FRR parity)

| Item | Matrix row | Notes |
|---|---|---|
| **Type-2 symmetric IRB** | L2 unicast / L3 | Originate Label2 = L3VNI, the VRF's route targets and the Router's-MAC EC on MAC/IP routes whose L2VNI bridge is in a VRF with an L3VNI; import received ones as `/32` and `/128` host routes in the VRF (bridge Type-5 path), and into the VRF BGP table as FRR does. The matrix's "Symmetric IRB" covers Type-5 only |
| **Duplicate address detection** | MAC mobility | FRR's `dup-addr-detection` (moves within a window → freeze) |
| **ARP suppression verification** | ARP suppression | Namespace check that kernel suppression answers from the installed bindings; then update the row |
| **Type-2 write amplification** | — | Each Type-2 change rewrites the MAC's kernel entries and re-checks each IP; measure at ~1k MACs |
| **IPv6 VTEPs on the bridge Type-5 path** | IPv6 underlay | Not qualified |
| **VLAN-aware fixed-VNI bridges** | L2 unicast | Not qualified |
| **Runtime `kernel-route-exchange` toggle** | L3 / Type-5 | Configure before sessions; active routes are not replayed |
| **OVN: learn only BGP routes** | — (external) | Tracked in the OVN tree (`TODO.rst`, `dynamic-routing-learn-protocols`): with `proto zebra` statics, OVN learns VRF statics as it does FRR's |

## Validation snapshot

* `cargo test --workspace --exclude bdd` and `--features lua`: pass.
* Root-only kernel tests: 6/6. Linux namespace test: 125/125.
* BDD (all features): the only failure attributable to this work
  (`bgp_evpn_local_mac`) is fixed in #2488; the others fail identically on
  `main` on the test host (no cradle engine, iproute2 6.1) or are
  load-sensitive (`stamp_loss`).
