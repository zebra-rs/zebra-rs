# Lua Egress (Adj-RIB-Out) Hook — design note

Status: **E1–E4 complete** — egress hook wired and config-bindable for IPv4-unicast and
L2VPN-EVPN. (E5, the Model-B opt-in / restricted-identity table, remains deferred.)
Builds on the merged Lua scripting series (engine, import/withdraw hooks, marshalling,
host helpers) — see `docs/design/lua-scripting-policy.md`.

## Decision (confirmed 2026-06-22)

- **Correctness model: B — singleton group per scripted peer.** Folding the bound
  script identity *plus a peer-unique key* into `UpdateGroupSig` makes any peer with an
  egress script its own update-group; the black-box transform then runs **per-peer with
  the full `peer` table**, never replicating one peer's bytes to another. This trades
  update-group coalescing (for scripted peers) for unconditional correctness and full
  peer context — chosen over Model A. The §3 analysis below is kept for the rationale.
- **Config surface: a new `adj-rib-out-hook` container** (separate from `loc-rib-hook`,
  since Adj-RIB-Out is a different RIB boundary).
- **Status:** E1 (engine `adj_rib_out` / `adj_rib_out_evpn` entries + egress bindings +
  `generation()`) and E2 (`UpdateGroupSig.egress_script` = [`EgressScriptKey`] {name,
  generation, peer} + `SIGNATURE_VERSION = 4` + `signature_of`) are implemented and
  unit-tested. **E3 is done**: the v4 egress hook is wired into
  `route_apply_policy_out` (via `SyncCtx::apply_egress_v4`, with `remote_id`/
  `remote_address` added to `SyncCtx` so the egress `peer` table is complete), bound by
  `adj-rib-out-hook ipv4-unicast export`, and a binding change reassigns every
  established peer's update-group (`reassign_all_update_groups`) so the singletons form
  before the transform runs. E4 (EVPN advertise via `route_apply_policy_out_evpn`) is
  next. Under Model B the egress hook **does**
  receive the full `peer` table (it runs per-peer), unlike the no-peer-table design A
  sketched in §3.

## 1. Goal

The merged hooks cover the **receive** side. This adds the **advertise** side: a hook
that runs as a route is built into a peer's Adj-RIB-Out, after native outbound policy,
and may **transform the attributes** before they are encoded. The motivating use case
is the GBP-over-EVPN talk's *origination* half — attach the GPI Extended Community
(`0x03/0x17`, the group tag) to the EVPN Type-2 route on the way out:

```lua
function adj_rib_out(prefix, attributes, RM_FAILURE, RM_NOMATCH, RM_MATCH, RM_MATCH_AND_CHANGE)
    local mac = prefix.evpn and prefix.evpn.mac
    if mac then
        local tag = map.get("sgt", mac)              -- non-blocking lookup
        if tag then
            table.insert(attributes.ext_community, ecom.gpi(tonumber(tag)))
            return { action = RM_MATCH_AND_CHANGE, attributes = attributes }
        end
    end
    return { action = RM_NOMATCH }
end
```

Reuses the engine, marshalling, write-back (`read_attr`), and `ecom.gpi`/`map.get`
host helpers already on `main`. **The hard part is not the hook — it is update-group
coalescing.**

## 2. The hard problem: update-group coalescing

zebra-rs does not encode an UPDATE per peer. Peers that would receive **byte-identical**
UPDATEs are grouped (`UpdateGroupSig`, `update_group.rs:120`); one *canonical member*
runs the egress transform + encodes once, and the bytes are replicated to every member
(`docs/design/bgp-egress-*`). This is a large convergence win and the default path.

The grouping is sound **only because the canonical-member transform output is assumed
to depend solely on the signature fields.** Every native per-peer egress transform that
*could* differ between peers is folded into `UpdateGroupSig` so peers that would diverge
land in different groups:

- `policy_out_name`, `prefix_set_out_name` — the bound out-policy.
- `as_override_target = remote_as` — as-override rewrites the peer's AS, so the output
  depends on `remote_as`; two peers may only share if they override the *same* AS.
- `remove_private_as` (mode + kept AS), `local_as_substitute` — same reasoning.
- `local_as`, `peer_type`, `reflector_client`, `local_addr`, negotiated caps.

`signature_of` (`update_group.rs:310`) builds this; `SIGNATURE_VERSION` (currently **3**)
is bumped whenever a field is added (surfaced in `show bgp update-group`).

**A Lua egress script is a black box.** The engine cannot know which inputs it reads.
If a script branches on `peer.remote_as` (or any non-signature peer field), two peers in
the same group but with different `remote_as` would both get the **canonical member's**
output — silently wrong, and a BDD would not catch it (the bytes look fine; only the
*wrong* peer's bytes). This is the exact trap the memory note
`zebra-rs-bgp-update-group-signature-trap` warns about, generalized to an arbitrary
transform.

## 3. Two correctness models

### Model A — purity contract + sig-keyed sharing (recommended)

Treat the egress hook the way native transforms are treated: **it must be a pure
function of `(prefix, attributes)` and the signature-invariant identity** — nothing
peer-specific outside the signature.

Enforce it structurally rather than by documentation:

- The egress hook is passed **`prefix` and `attributes` only — no `peer` table** (v1).
  Within a group, all members share the same pre-transform `attributes` for a given
  route, and the same prefix, so the transform output is identical for the whole group.
  Any group-invariant identity the script legitimately needs (local-AS, iBGP/eBGP,
  reflector-client) is *already* a signature field; if a real need appears, expose a
  **restricted** `egress` table carrying only those signature-invariant fields (still
  safe), never arbitrary peer state.
- Add the bound script identity to `UpdateGroupSig` so enabling / disabling / reloading
  the script forces a regroup + recompute (§4).

Result: coalescing is preserved (the GBP origination transform is a pure function of the
route, so all members of a group get the correct, identical bytes), and the canonical-
member assumption still holds.

The remaining soft spot is **non-determinism inside the script** — e.g. `map.get`
returning a different value on two calls within the same flush, or `Math.random`-style
sources (already removed by the sandbox). `map.get` is the realistic one: the canonical
member runs the transform once per route per flush, so a mid-flush map change can only
make *the next* flush differ, never split one group's members — the map is read once per
canonical encode and replicated. That is acceptable (eventual consistency on the next
advertise), and is called out in §7.

### Model B — singleton group per egress-scripted peer (fallback)

If we are unwilling to rely on the purity contract, make any peer with an egress script
its **own** update-group (fold the peer's identity into the signature when a script is
bound), so the script runs per-peer with full peer context. Correct unconditionally, but
loses coalescing for scripted peers (N encodes instead of 1). Keep this as an opt-in
(`adj-rib-out-hook … per-peer`) or a fallback if a future hook needs real peer state.

**Recommendation: ship Model A** (no `peer` table → purity is structural), with Model B
noted as the escape hatch. v1 binding is **global per-AFI** (one egress script for the
family), which does not shard groups at all — it only needs to ride the signature so a
reload invalidates cached encodings.

## 4. UpdateGroupSig integration

```rust
pub struct UpdateGroupSig {
    // … existing fields …
    /// Bound egress (Adj-RIB-Out) Lua script for this family: `(name,
    /// generation)`. `None` when unbound. The generation makes a hot
    /// reload bump the signature, so every group re-forms and the
    /// canonical member re-encodes with the new script. With a global
    /// per-AFI binding every peer carries the same value, so this does
    /// not shard groups — it gates cache validity. (Per-peer bindings,
    /// if added later, would shard here, which is exactly correct.)
    pub egress_script: Option<(String, u64)>,
}
```

- Bump `SIGNATURE_VERSION` 3 → **4**.
- `signature_of`: `egress_script: script::egress_binding(afi, safi)` (the bound name +
  `script::generation()`), `None` when unbound or the `lua` feature is off.
- Add a column to `show bgp update-group` (the sig is already rendered there).

The script `generation` is the registry counter already used for lazy VM recompile;
expose a `script::generation()` getter (read of the existing `Scripts.generation`).

## 5. Firing point

Native outbound policy is `route_apply_policy_out` (v4, `route.rs:2790`) /
`route_apply_policy_out_evpn` (`route.rs:2767`), both returning `Option<PolicyDecision>`
and both consulted by the canonical-member encode (`route.rs:3817`, `4304`, `4951`).
Hook **after** the native decision, mutating `decision.attr`:

```rust
let decision = route_apply_policy_out(&ctx, &nlri, attr, weight)?;
#[cfg(feature = "lua")]
let decision = script::adj_rib_out_v4(IpNet::V4(nlri.prefix), decision); // Failure→None, Change→new attr
```

Because this is the canonical member's single encode, the script runs **once per group
per route**, and the bytes replicate — correct under Model A. The egress engine entry is
the existing `run_import_prefix` machinery renamed conceptually (`adj_rib_out`), reusing
`MATCH_AND_CHANGE` write-back; `Failure` means "don't advertise this route to the group".

EVPN advertise hooks at `route_apply_policy_out_evpn` the same way (`prefix.evpn`).

## 6. Config / YANG

A new container (the egress boundary is Adj-RIB-Out, distinct from `loc-rib-hook`):

```
router bgp 65000
  adj-rib-out-hook {
    ipv4-unicast { export GBP_OUT; }
    l2vpn-evpn   { export GBP_OUT; }
  }
```

`zebra-bgp-lua.yang`: an `adj-rib-out-hook` container mirroring `loc-rib-hook`, leaf
`export`. Handler → `script::set_egress_binding(afi_safi, Some(name))`; the binding lives
in the global script registry (like the import binding) so `signature_of` and the encode
path both read it without threading new fields through `BgpTop`/`SyncCtx`. Setting/
clearing the binding must **trigger a regroup** (the sig changed) — reuse the existing
update-group rebuild that a policy-out change already triggers.

## 7. Risks & mitigations

- **Canonical-member correctness** — addressed by Model A (no `peer` table → pure
  transform). The sig unit test (below) is the gate, not BDD.
- **`map.get` non-determinism within a flush** — read once per canonical encode and
  replicated; a mid-flush change shows up on the next advertise. Acceptable; documented.
  (A future "snapshot map at flush start" is possible if strict consistency is needed.)
- **Reload churn** — a generation bump re-forms every group with an egress script and
  re-encodes. Rare (config event); same cost as changing an out-route-map. The generation
  is per *script set*, so editing an unrelated script also bumps it — acceptable, or
  refine to per-script generations later.
- **Performance** — one extra script call per group per route on the canonical member
  (not per peer). Bounded; the egress task already fans encodes across a worker pool.
- **`UpdateGroupSig` version bump** — `show bgp update-group` surfaces v4; any external
  parser of that output must tolerate the new column. Internal only today.

## 8. Phased PRs

| PR | Content | Test |
|----|---------|------|
| E1 | `script::set_egress_binding` / `egress_binding` / `generation`; engine `adj_rib_out` entry (reuse `run_import_prefix` + write-back); **no** wiring yet. | unit: egress transform adds GPI ecom; Failure drops. |
| E2 | `UpdateGroupSig.egress_script` + `SIGNATURE_VERSION = 4` + `signature_of` + `show` column. | **sig unit test**: two peers, different egress bindings → different sigs; same binding+gen → same sig; reload (gen bump) → sig changes. |
| E3 | wire the hook into `route_apply_policy_out` (v4) + config/YANG (`adj-rib-out-hook ipv4-unicast export`) + regroup-on-bind. | unit: bound egress script transforms the advertised attr via the canonical encode. |
| E4 | EVPN: `route_apply_policy_out_evpn` + `l2vpn-evpn export`. | unit: EVPN advertise adds GPI ecom. |
| E5 | (deferred) Model B opt-in (`per-peer`) + restricted `egress` identity table, if a need appears. | |

E2 is the keystone — landing the `UpdateGroupSig` field with its unit test *before* the
wiring (E3) makes the coalescing-correctness contract explicit and regression-proof.

## 9. Open questions for review

1. **Binding name/shape** — `adj-rib-out-hook … export` vs folding `export` into the
   existing `loc-rib-hook` container. (Proposed: separate container, since it is a
   different RIB boundary.)
2. **`peer` table on egress** — v1 omits it (purity). Confirm we don't need a restricted
   identity table on day one.
3. **Model A vs B default** — proposed A (purity contract). Confirm before E2.
4. **Per-script vs per-set generation** — v1 uses the existing per-set generation in the
   sig (a coarse but correct reload signal). Refine later only if churn matters.
