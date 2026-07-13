# eBPF/XDP offload consolidation: one dataplane tree in cradle-rs

## Problem

There are two independent eBPF/XDP source trees today:

1. **zebra-rs `offload/`** — two self-contained aya workspaces, each a managed
   child process zebra-rs spawns and drives over a stdin line protocol:
   - `offload/xdp-bfd-echo/` — XDP BFD Echo reflector + originator + control-packet
     expiration watchdog (`bpf_timer`). Supervisor: `zebra-rs/src/bfd/reflector.rs`.
     Binary: `/usr/sbin/xdp-bfd-echo`, env override `ZEBRA_XDP_BFD_ECHO_BIN`.
   - `offload/tc-evpn-replicate/` — TC/clsact RFC 9524 SR P2MP BUM replication
     (`End.Replicate`, leaf `End.DT2M`, root `H.Encaps`). Supervisor:
     `zebra-rs/src/rib/evpn_replicate.rs`. Binary: `/usr/sbin/tc-evpn-replicate`,
     env override `ZEBRA_TC_EVPN_REPLICATE_BIN`.

2. **cradle-rs `crates/cradle-ebpf/`** — the monolithic XDP + TC dataplane
   (`cradle_xdp`, `cradle_tc`, `cradle_egress`), ~4k LOC, driven by the
   `cradle` userspace daemon over the `cradle.proto` gRPC API. zebra-rs already
   spawns and supervises `/usr/bin/cradle` (`system ebpf enabled`) and tees the
   FIB to it — see [[zebra-rs-cradle-embed-plan]].

Both are AGPL-3.0-or-later, same author. Maintaining two eBPF trees costs us:

- **Two toolchains / two packagings.** cradle-rs is eBPF-native (pins nightly in
  `rust-toolchain.toml`, installs bpf-linker in CI, builds + clippies the BPF
  object on every PR). zebra-rs deliberately is not: `offload/` is workspace-
  excluded so the stable CI gate never sees it. `xdp-bfd-echo` is the *only*
  reason zebra-rs's packaging workflows install nightly + LLVM 18 + bpf-linker.
- **A CI blind spot.** `offload/tc-evpn-replicate` is built by **no** CI and
  shipped in **no** package today — it can rot silently.
- **Unpinned aya.** Both offload trees ride `aya = { git = ".../aya" }` with no
  pinned rev; the READMEs already flag "pin a rev for reproducible builds" as a
  follow-up.
- **A latent XDP-attach conflict.** Only one XDP program can own an interface.
  Enabling `interface X ebpf` (cradle's `SetPort` attaches `cradle_xdp`) and BFD
  `echo-mode` / `detect-offload` on the same interface would have `xdp-bfd-echo`
  and `cradle_xdp` fighting over the hook. On a cradle-managed port, BFD echo
  *must* eventually be a branch inside `cradle_xdp`.

cradle-rs's own design docs already name both offload trees as absorb targets
(`cradle-rs/docs/design/architecture.md`, `.../tailcall-vs-monolithic.md`).

## Decision

**cradle-rs becomes the single home for all eBPF/XDP dataplane code.** The other
direction (fold cradle into zebra-rs) is wrong: it would drag a standalone
product — CNI plugin, K8s controller, Hubble/Cilium compat, its own deb and
users — into a routing daemon's repo and force nightly onto zebra-rs's stable CI.

Consolidation splits into two independent kinds of work; do not conflate them:

- **Tree consolidation** (Phase 0) — *where the source lives*: one toolchain,
  one CI, one deb. Cheap, mechanical, additive, reversible. No behavior change.
- **Engine consolidation** (Phases 1–2) — the offload *functionality* folds into
  `cradle_xdp` / `cradle_tc` and is driven over the existing gRPC tee instead of
  the stdin line protocols. The real architectural work; per-feature; later.

## Phase 0 — relocate the trees (no behavior change)

Two PRs, sequenced (cradle-rs first, so the binaries ship before zebra-rs stops
building them):

### Phase 0a — cradle-rs import (additive)

- Import both offload workspaces as cradle-rs workspace members, mirroring the
  `cradle-ebpf` layout:
  - `offload/xdp-bfd-echo/loader` → `crates/xdp-bfd-echo`
  - `offload/xdp-bfd-echo/ebpf` → `crates/xdp-bfd-echo-ebpf`
  - `offload/tc-evpn-replicate/loader` → `crates/tc-evpn-replicate`
  - `offload/tc-evpn-replicate/ebpf` → `crates/tc-evpn-replicate-ebpf`
- **Normalize onto cradle's pinned aya** (`aya 0.14 / aya-ebpf 0.2 /
  aya-build 0.2`), replacing the unpinned aya git deps — this also closes the
  "pin a rev" follow-up. Reuse cradle's `[workspace.dependencies]`; add the few
  offload-only ones (`env_logger`, `libc`, `log`, `which`). Simplify each loader
  `build.rs` to the cradle style (hardcoded ebpf package name + `root_dir`),
  dropping the `cargo_metadata` build-dep.
- Root manifest: add all four to `members`; add only the two loaders to
  `default-members` (the `-ebpf` crates build for `bpfel-unknown-none` only, via
  the loaders' `build.rs`); add `[profile.*.package.*-ebpf]` entries mirroring
  `cradle-ebpf`.
- CI: extend the `--workspace --exclude` lists in `clippy` and `test` with
  `--exclude xdp-bfd-echo-ebpf --exclude tc-evpn-replicate-ebpf`.
- Package both binaries from the cradle-rs deb at the **same paths** zebra-rs
  already resolves — `/usr/sbin/xdp-bfd-echo`, `/usr/sbin/tc-evpn-replicate` —
  with a setcap postinstall (finally packaging `tc-evpn-replicate`).
- Bring the `veth-*.sh` validation scripts + READMEs along.
- The two stdin line protocols become a cross-repo contract; document them in
  cradle-rs.

### Phase 0b — zebra-rs removal (gated on 0a shipping)

- Delete `offload/`, drop `exclude = ["offload/*"]` from the root `Cargo.toml`.
- Strip nightly / LLVM 18 / bpf-linker from `.github/workflows/build-debs.yaml`
  and `packaging/Makefile`; remove the helper from `packaging/nfpm-*.yaml`
  (the cradle-rs deb ships it now). zebra-rs packaging returns to pure stable.
- **Zero code change** in `bfd/reflector.rs` / `rib/evpn_replicate.rs`: same
  binary paths, same env overrides, same stdin protocols.
- BDD hosts treat the two helpers as prerequisites exactly as `/usr/bin/cradle`
  already is (see [[zebra-rs-cradle-embed-plan]]).

## Phase 1 — absorb `tc-evpn-replicate` into the engine (do this first)

More overlap with cradle's existing machinery than the BFD helper: `REPL_SID` /
`ReplTarget` slots, `l2_srv6_encap` / `l2_vxlan_encap` / `l2_overlay_encap`,
`flood()`, `VniInfo` — cradle already does root-style BUM fan-out. Genuinely new:

- **`End.Replicate` midpoint** — clone-per-leaf with outer-DA rewrite. Lands in
  `cradle_tc` (cloning needs `bpf_clone_redirect`, which XDP lacks).
- **`End.DT2M` leaf decap-to-bridge** — close to cradle's existing SRv6 L2 decap.

Control plane: new gRPC verbs (or an extended `ReplSlot` / `AddLocalSid` kind),
teed through `CradleFib` — which gets mirror+replay across engine restarts for
free (the stdin child never had that). Then delete `rib/evpn_replicate.rs` + the
standalone tree; migrate `bgp_evpn_srv6_p2mp.feature` to engine mode.

## Phase 2 — absorb BFD echo / watchdog into `cradle_xdp` (helper stays until done)

Harder, for three reasons:

- The `bpf_timer` machinery (per-session detection state in BTF maps) ports into
  `cradle-common` / `cradle-ebpf`.
- cradle needs its first **event stream back to zebra** (`echo-down` /
  `detect-down`) — a `WatchBfd` stream, precedent `WatchFdb`.
- `cradle_xdp` sits near the 448-byte XDP stack wall already hit in the VXLAN
  work ([[cradle-evpn-vxlan-phase1]]); the echo branch needs the same
  borrow-from-map discipline.

The 905-line AF_PACKET originator stays userspace (moves into cradle's control
loop). Unlock: a port whose only role is BFD gets `SetPort` with a passthrough
role — `cradle_xdp` defaults to `XDP_PASS`, so kernel forwarding still works on
non-dataplane routers, and "BFD echo without the cradle engine" survives as a
single implementation. This is where the standalone helper truly dies and the
XDP-attach conflict becomes structurally impossible.

## Non-goal

A shared-crate-only approach (keep both trees, dedup the helper code) fixes none
of the structural problems — two toolchains, two packagings, the attach conflict
— and adds a third versioned artifact. Fine as an internal byproduct of
Phases 1–2 (`cradle-common` grows the shared types); wrong as an end state.

## Status

- 2026-07-12: strategy decided; this doc written.
- 2026-07-12: **Phase 0a merged** — cradle-rs PR #121 (`import-offload-helpers`,
  merge `722ae5a`). Both offload trees are now cradle-rs workspace crates on the
  pinned aya; CI (fmt/clippy/test) green. A stale-clippy-cache false pass hid a
  `doc_lazy_continuation` lint locally — CI caught it; fixed before merge.
- 2026-07-12: **Phase 0b implemented** — deleted zebra-rs `offload/`, dropped
  `exclude = ["offload/*"]`, stripped nightly/LLVM 18/bpf-linker from
  `build-{amd64,arm64,debs}.yaml` + `packaging/Makefile` + the root `Makefile`
  (`xdp-bfd-echo`/`install-xdp-bfd-echo` targets), removed the helper from both
  `nfpm-*.yaml` and its setcap from `packaging/scripts/postinstall.sh`. Only
  doc-comment path pointers changed in `bfd/reflector.rs`, `bfd/inst.rs`,
  `rib/evpn_replicate.rs` (now point at cradle-rs) — no logic change; the
  supervisors' binary resolution (`/usr/sbin/…` + `ZEBRA_*_BIN`) is untouched.
  Verified: `cargo metadata` OK, workflow/nfpm YAML parse, Makefiles clean.
- **Deployment gating (still true)**: this PR stops the *zebra-rs* deb from
  shipping the helper. A host must get the binaries from the cradle-rs deb — so
  do **not** cut a zebra-rs release that drops the helper until a cradle-rs
  release (≥ the Phase-0a import) is published and installed. Local dev/BDD keep
  working because `/usr/sbin/{xdp-bfd-echo,tc-evpn-replicate}` are already
  installed on this host.
- 2026-07-13: **BFD auto-attach implemented** (branch `bfd-ebpf-enable`) —
  realises the Phase-2 "a port whose only role is BFD gets `SetPort`" unlock on
  the *zebra* side. A single-hop `echo-mode`/`detect-offload` session now
  auto-enrols its egress interface as a cradle port, so `interface … ebpf
  enabled` is no longer required alongside `system ebpf enabled` for BFD
  offload (which S4 called out as datapath gap #3). Mechanism: an eager
  `ConfigManager` channel carries `cradle::PortRequest::{Acquire,Release}`
  edges from `EchoReflectors`' per-ifindex refcount to the cradle port
  supervisor, which folds them into `reconcile_ports` as a **union** with
  `if_ebpf`. Engine still gated on `system ebpf enabled` (chosen scope).
  `show ebpf` labels each port `config`/`bfd`/`config,bfd`.
</content>
</invoke>
