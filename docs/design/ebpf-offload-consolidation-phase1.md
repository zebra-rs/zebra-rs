# Phase 1: retire tc-evpn-replicate — converge EVPN BUM replication onto the cradle engine

Follows [ebpf-offload-consolidation.md](ebpf-offload-consolidation.md). Phase 0
relocated both offload trees into cradle-rs. Phase 1 addresses the
`tc-evpn-replicate` (RFC 9524 SR P2MP EVPN BUM) datapath.

## Investigation finding (the reason this is subtraction, not a port)

Mapping all three subsystems revealed that **cradle already replicates EVPN BUM
toward leaf `End.DT2M` SIDs**, driven from the *same* BGP compute that feeds the
standalone offload. The two datapaths are redundant for every topology the
control plane computes today:

- **Leaf decap (`End.DT2M`)** — cradle's `srv6_dt2u` (crates/cradle-ebpf/src/main.rs)
  handles both DT2U and DT2M decap-to-bridge. zebra already installs the leaf's
  local SID via `AddLocalSid` behavior 10 (`send_vni_l2_sid_add`,
  bgp/inst.rs). No new work; already the cradle path.
- **Root fan-out (`H.Encaps` toward leaves)** — at Type-3 IMET import
  (bgp/route.rs ~7360) zebra tees each remote leaf's `End.DT2M` SID via
  `CradleReplAdd` → `CradleFib::repl_slot_add` → `AddReplSlot`. cradle's
  `flood()` + `l2_srv6_encap` then emit one reduced-SRv6 copy per leaf. This is
  exactly the flat-tree root replication the standalone offload performs — and
  it is already mirror/replayed across engine restarts.
- **`End.Replicate` midpoint (bud)** — the *only* thing the standalone program
  adds that cradle lacks. But the control plane computes a **flat** tree
  (`replication_leaves` = every PE; `tree_id = vni`); the multi-tier bud tree is
  a deferred, uncomputed follow-up. So the midpoint eBPF is dead in practice.

**Decision (user, 2026-07-12): converge onto the cradle tee.** Retire the
`tc-evpn-replicate` supervisor + its RIB messages + the standalone crate; rely on
cradle's existing `AddReplSlot`/`srv6_dt2u` path. No new eBPF. The in-engine
`End.Replicate` midpoint is forgone until a real multi-tier tree is built (then
it lands as a proper engine feature, not a resurrected child process).

## What stays vs goes

**KEEP (already the cradle datapath):**
- `CradleReplAdd`/`CradleReplDel` tee at IMET import (bgp/route.rs ~7360, ~7208).
- `CradleFib::repl_slot_add/del` + `AddReplSlot`/`DelReplSlot` (fib/cradle.rs).
- Leaf `End.DT2M` local-SID tee (`send_vni_l2_sid_add`, bgp/inst.rs) →
  `AddLocalSid` → `srv6_dt2u`.
- The BGP compute of the leaf set from IMET (`sr_remotes`, `sr_remote_sids`).
  The cradle path consumes the imported SIDs directly.

**REMOVE (the redundant supervisor datapath):**
- zebra-rs `src/rib/evpn_replicate.rs` (the `ReplicationHelper` supervisor) and
  the `Rib::evpn_repl` field.
- RIB messages `ReplSegAdd`/`ReplSegDel`/`ReplLeafAdd`/`ReplLeafDel`/
  `ReplDataplaneCfg` and their `process_msg` arms.
- The `reconcile` → `ReplSegAdd` emission path (route.rs ~2768) and
  `replication_action`/`ReplAction`/`repl_installed` if unused after (verify:
  the cradle path is import-driven, not reconcile-driven).
- The `sr-p2mp-dataplane` YANG container + `EvpnSrDataplaneCfg` +
  `config_evpn_sr_dp_*` + `send_evpn_sr_dataplane`, and the
  `ZEBRA_TC_EVPN_REPLICATE_*` envs.
- cradle-rs `crates/tc-evpn-replicate` + `crates/tc-evpn-replicate-ebpf`
  (imported in Phase 0a; now dead) + their workspace/CI/packaging wiring.

## Slices (small, verify-before-delete)

- **S0 — verify** (no code): confirm the cradle tee path forwards SR P2MP BUM
  equivalently — the SRv6 `repl_slot_add` reduced-encap toward each leaf DT2M
  SID, driven for SR P2MP leaves, incl. withdraw / IR↔SR flip. Read the exact
  paths; if a gap exists, surface it before deleting anything.
- **S1 (zebra-rs)** — delete the supervisor: `rib/evpn_replicate.rs`, `evpn_repl`
  field, the five RIB messages + arms, the `reconcile` ReplSeg emission. Keep the
  IMET-import cradle tee untouched. Build + unit tests.
- **S2 (zebra-rs)** — remove `sr-p2mp-dataplane` YANG/config + the envs.
- **S3 (zebra-rs BDD)** — migrate `bgp_evpn_srv6_p2mp.feature` to engine mode:
  enable `system ebpf`, assert the cradle datapath (repl-slot / local-sid via
  `show ebpf`) instead of the child-process logs (`spawned`, `ReplSeg add`).
  Keep the RFC 8365-style teardown.
- **S4 (cradle-rs)** — delete `crates/tc-evpn-replicate{,-ebpf}`; revert their
  Phase-0a workspace/CI/nfpm/postinstall wiring. `xdp-bfd-echo` is untouched
  (Phase 2 owns it).

Each slice is its own PR. S1–S3 are one zebra-rs branch sequence; S4 a cradle-rs
PR. Order: S0 → S1 → S2 → S3 (zebra), then S4 (cradle) once the BDD proves the
engine path.

## Risk

Deleting a lab-validated datapath. Mitigation: S0 verification first; the cradle
path is already validated for EVPN/VXLAN and is import-driven from the same
compute. If S0 finds the SRv6-P2MP repl-slot path incomplete, stop and reassess
(the standalone datapath stays until the gap is closed).

## Status

- 2026-07-12: investigation done (3-subsystem map), Option A chosen, doc written.
- 2026-07-12: **S0 verified** — the cradle tee (`CradleReplAdd`→`AddReplSlot` +
  `AddLocalSid`→`srv6_dt2u`) forwards SR P2MP BUM, teed at IMET import
  independent of PMSI mode, with mirror/replay. Safe to retire the supervisor.
- 2026-07-12: **S1+S2 done** (branch `phase1-evpn-repl-converge`, commit
  `622861ee`, −1072 lines): deleted `rib/evpn_replicate.rs`, the 5 RIB messages,
  the `reconcile` ReplSeg emission, and the entire now-dead replication-segment
  compute (`replication_action`/`replication_leaves`/`ReplAction`, the
  `root`/`sr_remote_sids`/gateway-tree fields+methods+call sites+tests), plus the
  `sr-p2mp-dataplane` YANG/config + guard test. Kept `update_sr_remote`/
  `sr_remotes` (VXLAN-flood exclusion) and the cradle tee. Verified: check +
  clippy `--all-targets` clean, fmt, 1560 unit tests pass.
- **Next:** S3 (migrate `bgp_evpn_srv6_p2mp.feature` to cradle-engine mode — must
  land before S4, or the BDD, which still drives the standalone offload, breaks),
  then S4 (delete cradle-rs `crates/tc-evpn-replicate{,-ebpf}`). Each its own PR.
