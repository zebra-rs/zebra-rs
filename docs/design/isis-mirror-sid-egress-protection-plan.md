# IS-IS Mirror SID Egress Protection — Implementation Plan

Status: **PLAN / not yet implemented**. Branch: `isis-edge-protection`.

Source brief: `is-is-mirror-sid-egress-protection.md` (repo root).

Standards:
- RFC 8402 (Mirror Context segment architecture)
- RFC 8667 §2.4 (IS-IS SR-MPLS: SID/Label Binding TLV 149 + M-flag)
- RFC 8679 (MPLS Egress Protection Framework — context label)
- RFC 9352 (IS-IS SRv6 Locator TLV 27 — container for the new sub-TLV)
- RFC 8986 (SRv6 Network Programming — End.M is an End.DT6 variant)
- draft-ietf-rtgwg-srv6-egress-protection-23 (SRv6 End.M function 74 + Protected-Locators sub-sub-TLV)
- RFC 9855 / our existing TI-LFA (complementary; PLR repair-list reuse)

---

## 1. What we are building

Three cooperating roles. Mirror SID closes the gap TI-LFA cannot: protecting the **egress PE itself** (node) and the **PE–CE link**.

| Role | Node | Responsibility |
|------|------|----------------|
| **PEA** | Primary egress | Normal egress forwarding. For *link* protection PEA is also its own PLR. |
| **PEB** | Protector / backup egress | Advertises `<PEB, PEA, Mirror SID>` + protected locator(s); builds a **mirror-context FIB** reproducing PEA's service forwarding; runs **End.M** (decap → context lookup). |
| **PLR** | P1 (neighbor of PEA), or PEA itself for link protection | On PEA/link failure, pushes the Mirror SID (+ repair list) and steers to PEB. |

CE is dual-homed to PEA and PEB. Service forwarding state is learned at PEB via **BGP L3VPN overlay** (RFC 9252), *not* flooded per-service in the IGP. The IGP only carries the locator-level `<PEB, PEA, Mirror SID>` binding.

---

## 2. The key dataplane insight (de-risks the whole feature)

**SRv6 — there is no native kernel `End.M` action, and we don't need one.**

End.M behavior per RFC 8986 / the draft = "verify SID is local; remove the outer IPv6 header + extension headers; submit the *inner* packet to the FIB table bound to this SID's context." That is **identical to `seg6local End.DT6` / `End.DT46` with a `table` / `vrftable` argument** — which `zebra-rs/src/fib/netlink/srv6.rs:191-241` (`build_seg6local_lwtunnel`) already emits (see the `EndDT46 → VrfTable(table_id)` arm at lines 226-231).

So the protector decap is:

```
outer DA = Mirror SID  --(End.M = End.DT6 table=M)-->  strip outer, lookup inner DA in table M
table M:  PEA-service-SID/128  --(End.DT46 vrftable=V)-->  PEB's VRF V  -->  CE
```

Both hops are ordinary seg6local localsids the codebase already programs. The *new* dataplane primitive is just "a dedicated **mirror-context routing table** `M`, plus the ability to install a localsid whose lookup `table` is `M`." No new kernel feature, no new netlink action.

**SR-MPLS — harder, deferred to a later phase.** RFC 8679's context label requires a per-context label table; Linux AF_MPLS is a single global ILM table (`rib/inst.rs:720` comment; `IlmType` at `rib/inst.rs:349-373`). We implement the control plane (Binding TLV 149 + M-flag, PLR push) fully, and approximate the dataplane by installing PEA's context labels directly into PEB's global ILM mapped to PEB's VRF (valid under the draft's "structured dual-homing, modest service count" scope, and fully controllable in BDD). This limitation is documented and gated behind its own phase.

**PLR side — almost entirely existing TI-LFA machinery.** `Nexthop::Protect{primary,backup,gid}` (`rib/nexthop/inst.rs:188-200`), the `RepairPath`/`SrSegment` builder (`spf/calc.rs:414-605`), the ~6 Protect consumer sites (already complete), and BFD-driven `protect_switch` (`isis/inst.rs:2675` → `rib/route.rs:1644-1702`) all exist. The only addition: build the backup `NexthopUni.segs = [repair_segs…, Mirror_SID]` (SRv6) or `mpls_label = [repair_labels…, ctx_label]` (SR-MPLS).

---

## 3. Subsystem map (where each change lands)

| Concern | File(s) | Anchor |
|--------|---------|--------|
| TLV enum + dispatch | `crates/isis-packet/src/parser.rs` | enum 509-569, emit 589-621, `parse_tlv` 1340-1354 |
| TLV type codes | `crates/isis-packet/src/tlv_type.rs` | 6-54 (add `SidLabelBinding = 149`) |
| SRv6 Locator TLV 27 | `crates/isis-packet/src/sub/prefix.rs` | `IsisTlvSrv6` 819-855, `Srv6Locator` 760-768 |
| SRv6 End SID sub-TLV / sub2 | `crates/isis-packet/src/sub/prefix.rs` | `IsisSubSrv6EndSid` 77-129, `IsisSub2Tlv` 156-197 |
| SRv6 behavior enum | `crates/isis-packet/src/sub/srv6.rs` | `Behavior` 10-80, From impls 120-192 (add `EndM = 74`) |
| Prefix sub / sub2 codes | `crates/isis-packet/src/sub/prefix_code.rs` | `IsisPrefixCode` / `IsisSrv6SidSub2Code` |
| Sub-TLV length helper | `crates/isis-packet/src/util.rs` | `emit_sub_tlvs` 5-14 |
| Codec round-trip tests | `crates/isis-packet/tests/parser.rs` | `parse_emit` 5-19, `parse_srv6` 299-331 |
| IS-IS module layout | `zebra-rs/src/isis/` | inst/rib/lsp/lsdb/srv6/tilfa/config/show |
| SRv6 locator → SID alloc | `zebra-rs/src/isis/srv6.rs` | `ElibPool` 23-68, `function_addr` 82-90 |
| LSP origination (SRv6 loc) | `zebra-rs/src/isis/lsp.rs` | 828-872 |
| Remote SRv6 reception | `zebra-rs/src/isis/lsdb.rs` | 456-507 → `srv6_end_map`, `peer_algo_srv6` |
| SID registry (show + install) | `zebra-rs/src/rib/segment_routing/sid.rs` | `Sid` 201-223 |
| seg6local install | `zebra-rs/src/fib/netlink/srv6.rs` | `build_seg6local_lwtunnel` 191-241 |
| seg6 (H.Encaps) install | `zebra-rs/src/fib/netlink/srv6.rs` | `build_seg6_lwtunnel` ~32 |
| MPLS ILM types | `zebra-rs/src/rib/inst.rs` | `IlmType` 349-373, `IlmEntry` 382-413 |
| MPLS ILM netlink | `zebra-rs/src/fib/netlink/handle.rs` | `ilm_add` 2021-2168 |
| SRGB/SRLB blocks | `zebra-rs/src/rib/segment_routing/block.rs` | 14-34 |
| TI-LFA repair list | `zebra-rs/src/spf/calc.rs` | `RepairPath` 529, `make_repair_list` 437-526 |
| IS-IS TI-LFA binding | `zebra-rs/src/isis/tilfa.rs` | `tilfa_targets` 521, `tilfa_repair_path` 579 |
| Protect nexthop | `zebra-rs/src/rib/nexthop/inst.rs` | `Nexthop::Protect` 110-116, `NexthopProtect` 188-200 |
| BFD → switch | `zebra-rs/src/isis/inst.rs` / `zebra-rs/src/rib/route.rs` | `process_bfd_event` 2675 / `protect_switch` 1644-1702 |
| BGP VPN import + remote SID | `zebra-rs/src/bgp/vrf/inst.rs`, `crates/bgp-packet/src/bgp_attr.rs` | `srv6_l3_sid()` |
| BGP per-VRF End.DT46 | `zebra-rs/src/bgp/vrf/spawn.rs` | 225-248 `send_sid_add` |
| BGP↔RIB SR/locator sync | `zebra-rs/src/bgp/inst.rs` | `RibSrRx::Locator`, colour-steering shadow |
| YANG config | `zebra-rs/yang/config.yang` | isis 1389, segment-routing 1462-1506, fast-reroute 1606-1658 |
| Config handlers | `zebra-rs/src/isis/config.rs` | `callback_build` 48-160, `config_ti_lfa` 1385-1403 |
| YANG show grammar | `zebra-rs/yang/exec.yang` | isis 553-716, sr/srv6 863-874 |
| Show renderers | `zebra-rs/src/isis/show.rs`, `zebra-rs/src/rib/show.rs` | `show_build` 22-79, `sid_show` 1888-1954 |
| BDD features / steps / configs | `bdd/tests/features/`, `bdd/tests/cucumber.rs`, `bdd/tests/configs/` | template `isis_tilfa_srv6.feature` |

---

## 4. Phased plan

Principle (per project feedback notes): **smallest mergeable PR first**; each phase compiles, passes `cargo fmt` + workspace clippy + tests, and leaves no half-wired state. **SRv6 lands end-to-end first** (lowest dataplane risk — pure End.DT6 reuse), **SR-MPLS second**. Each phase is its own branch off `isis-edge-protection` (or a fresh branch off `main` once we agree on stacking).

### Phase 0 — Plan & branch (this document)
- This design doc. No code.

### Phase 1 — Packet codec (pure, isolated, fully unit-tested)
PR 1a (SRv6 codec):
- `Behavior::EndM = 74` in `sub/srv6.rs` (+ both `From` arms).
- New `IsisSubSrv6MirrorSid` sub-TLV (suggested code 8) for the SRv6 Locator TLV, carrying flags + behavior(=EndM) + 16-octet SID + `sub2s`.
- New sub-sub-TLV `IsisSub2ProtectedLocators` (suggested code 1 within the Mirror SID scope): `locator-size: u8` + variable locator bytes. **Exactly one** required per Mirror SID sub-TLV.
- Wire both into `IsisSubTlv` / `IsisSub2Tlv` enums + emit/len arms + `prefix_code.rs`.
- Round-trip tests in `tests/parser.rs` mirroring `parse_srv6` (build → emit → re-parse → assert fields).

PR 1b (SR-MPLS codec):
- `IsisTlvType::SidLabelBinding = 149` + `IsisTlv::SidLabelBinding(IsisTlvSidLabelBinding)` variant + emit arm.
- `IsisTlvSidLabelBinding { flags: BindingFlags, range?, prefix, subs }`; `BindingFlags` bitfield incl. **M-flag (Mirror Context)**.
- Reuse existing SID/Label sub-TLV; enforce invariant in *origination* (M-set ⇒ SID/Label sub-TLV present, Prefix-SID sub-TLV absent) — codec stays permissive, validation in the IS-IS layer.
- Round-trip tests.

*Verification:* `cargo test -p isis-packet`. No behavioral change anywhere else.

### Phase 2 — Config model + internal state (no dataplane)
- YANG: add under `router isis` a `container egress-protection` (sibling of `fast-reroute`), e.g.:
  ```
  container egress-protection {
    list protect {
      key protected-node;            // PEA system-id or hostname
      leaf protected-node { type string; }
      leaf protected-locator { type inet:ipv6-prefix; }   // SRv6
      leaf mirror-sid { type inet:ipv6-address; }          // optional; auto-allocate if absent
      leaf via-vrf { type string; }                        // local VRF that reaches the CE
      leaf dataplane { type enumeration { enum srv6; enum mpls; } default srv6; }
    }
  }
  ```
- `config.rs`: register `/router/isis/egress-protection/protect` callbacks (mirror `config_sr_srv6_locator` / `config_ti_lfa`); store into a new `EgressProtectionConfig` on `Isis`; trigger `LspOriginate` + `SpfCalc` on change.
- New state structs in `isis/` (new module `egress_protection.rs` sibling to `tilfa.rs`/`srv6.rs`): `MirrorProtect { protected_node, protected_locator, mirror_sid, via_vrf, dataplane }`, plus a `mirror_db` for **received** advertisements (filled in Phase 6).

*Verification:* config applies, shows up in running config, no forwarding effect. Unit test the handler.

### Phase 3 — PEB SRv6 origination + show
- Allocate the Mirror SID from the configured parent locator (reuse `isis/srv6.rs` `ElibPool` / `function_addr`; Mirror SID inherits topology/algorithm from the parent locator per the draft). Register it in the central `Sid` registry (`rib/segment_routing/sid.rs`) with a new `SidBehavior::EndM` + `owner = isis` + the context table id (allocated in Phase 4).
- `lsp.rs`: emit the `IsisSubSrv6MirrorSid` sub-TLV (with `IsisSub2ProtectedLocators`) inside the SRv6 Locator TLV for the configured protections.
- `show.rs` + `exec.yang`: `show isis egress-protection` listing `<protected-node, protected-locator, mirror-sid, dataplane, state>`; extend `show segment-routing srv6 sid` to render End.M entries.

*Verification:* a 2-router BDD slice asserts PEB's LSP / show output carries the Mirror SID + protected locator (peer LSDB inspection), no dataplane yet.

### Phase 4 — PEB SRv6 dataplane (End.M decap + context table)
- Allocate a dedicated **mirror-context routing table id** per protected node (RIB-side, analogous to how VRF table ids are tracked). Reserve a table-id band for mirror contexts.
- Install the Mirror SID localsid as `seg6local End.DT6 table <M>` (or `End.DT46`/`End.T` if inner may be v4) via `build_seg6local_lwtunnel` — set `behavior = EndM`, mapped to the `End.DT6 + table` netlink encoding. (Add `SidBehavior::EndM` → `Seg6LocalAction::EndDt6` + `Table(M)` in `seg6local_action` / the attr builder at `fib/netlink/srv6.rs:119-241`.)
- The context table `M` is empty until Phase 5 populates it.

*Verification:* `ip -6 route show table <M>` + the localsid present; unit/lab check that a packet to the Mirror SID decaps into table M (BDD comes in Phase 7).

### Phase 5 — PEB mirror-context FIB population
- **Primary path (BGP-learned):** when PEB imports a VPN route whose remote PE SID (`attr.srv6_l3_sid()`, `bgp_attr.rs`) falls inside a *protected locator* and the VRF is a configured `via-vrf`, install into context table `M`: `PEA-service-SID/128 → seg6local End.DT46 vrftable=<PEB's VRF table>`. Drive this from the existing BGP→RIB SR plumbing / colour-steering shadow-sync pattern (`bgp/inst.rs`, `BgpVrfMsg`), extended with a `MirrorContext` message carrying `(protected_sid, context_table, vrf_table)`.
- **Fallback (static config) for MVP/BDD decoupling:** the draft explicitly permits learning service behavior by configuration. Allow `egress-protection protect … via-vrf X` to mean "any inner SID landing in context M resolves in VRF X" — i.e. install a default `::/0 → End.DT46 vrftable=V` in table M, sidestepping per-SID BGP coupling for the first end-to-end test. Keep both; BGP-learned is the production path.

*Verification:* covered by Phase 7 BDD; plus a unit test of the import→context-install mapping.

### Phase 6 — PLR reception + repair installation
- `lsdb.rs`: parse received `IsisSubSrv6MirrorSid` (and Binding TLV 149 M-flag for SR-MPLS) into `mirror_db`: `protected_locator → {protector_node (PEB), mirror_sid}`.
- In the IS-IS RIB/SPF→FIB path (`isis/rib.rs`, `isis/tilfa.rs`): for prefixes whose primary egress is a protected node PEA (or whose nexthop is the protected PE–CE adjacency), build a backup using the existing TI-LFA repair-list to PEB, then **append/prepend the Mirror SID**:
  - SRv6: `backup.segs = [repair_segs… , mirror_sid]`; encode via `build_seg6_lwtunnel`.
  - Pair primary (→PEA) and backup into `Nexthop::Protect{primary, backup}`.
- Trigger: reuse `process_bfd_event` → `protect_switch(addr)`; the failed-nexthop addresses are PEA's adjacency addresses, which already key the Protect groups. Honor the draft's **stale-route retention** (PLR keeps the route to PEA after local convergence) — add a hold-down so upstream nodes still sending to PEA keep getting mirror protection.
- **Egress link protection variant:** PEA is the PLR for its own PEA–CE link; on PE–CE link/BFD down, PEA installs the same Protect backup (push Mirror SID → PEB).

*Verification:* Phase 7 BDD.

### Phase 7 — SRv6 end-to-end BDD (the milestone)
See §5. Node protection + link protection, dual-homed CE, BGP L3VPN service. This is the first fully-validated, demonstrable deliverable.

### Phase 8 — SR-MPLS variant
- Origination/reception of Binding TLV 149 + M-flag (codec from Phase 1b); allocate a **context label** from a dedicated pool (separate from SRGB/SRLB, `rib/segment_routing/block.rs`).
- New `IlmType::ContextLabel { context_table_or_vrf_ifindex }` in `rib/inst.rs` + `ilm_add` netlink (`handle.rs:2021`): pop the context label, deliver inner-label lookup into PEB's VRF (global-ILM approximation; documented limitation).
- PLR push: `backup.mpls_label = [repair_labels…, context_label]`.
- SR-MPLS BDD (mirror of `isis_tilfa.feature` + dual-homing).

### Phase 9 — Hardening & docs
- Stale-route retention timing, hold-down interplay with IS-IS hold-down gate, GR interaction, single-area scope guard (draft limitation), protector-consolidation warnings in show output.
- Update `book/` chapter (sibling to `ch-12-00-nexthop-protect.md`) and this doc → "implemented".

---

## 5. BDD test plan

Templates: `bdd/tests/features/isis_tilfa_srv6.feature` (8-router SRv6 + BGP L3 service) and `isis_srv6.feature` (4-router). Steps available: namespace/veth setup, `apply config`, `apply command`, link up/down, `show command … should (eventually) contain`, `kernel route … should eventually contain`, ping (v4/v6, eventual), BGP session state. Per global CLAUDE.md every feature **must** end with `Scenario: Teardown topology` stopping zebra-rs in each namespace, deleting each namespace, asserting `the test environment should be clean`. Unique feature tag (no tag may prefix another — concurrency-safety note).

### 5.1 SRv6 node protection — `bdd/tests/features/isis_mirror_sid_srv6.feature` (tag `@isis_mirror_sid_srv6`)

Topology (CE dual-homed; PEA is the protected egress, PEB the protector):
```
            +--- PEA (locator A3) ---+
 CE1 - PE1 - P1                       CE2   (CE2 dual-homed to PEA & PEB)
            +--- PEB (locator A4) ---+   PEB: Mirror SID A4::M protects A3::/64
```
6 namespaces: `ce1` (or fold into pe1), `pe1`, `p1`, `pea`, `peb`, `ce2`. IS-IS L2 + SRv6 everywhere; BGP L3VPN (VPNv6) PE1↔PEA and PE1↔PEB for the dual-homed VRF. `egress-protection protect pea protected-locator A3::/64 mirror-sid A4::M via-vrf cust` on PEB.

Scenarios:
1. **Build topology & converge** — start all, apply configs, wait, assert IS-IS adjacencies up, BGP Established, baseline `ping from pe1 to <CE2 VPN prefix> should eventually succeed` (via PEA primary).
2. **Mirror SID advertised & installed on PEB** — `show isis egress-protection` on PEB contains `A3::/64` + `A4::M`; PE1/P1 `show isis database detail` contains the Mirror SID; PEB `show segment-routing srv6 sid` contains `End.M`; `ip -6 route show table <M>` on PEB contains the context entry.
3. **PLR backup pre-installed** — on P1 (PLR), `show isis route detail` / nexthop shows a Protect backup toward PEB carrying the Mirror SID for the PEA-egress prefix (`kernel route … should contain` the seg6 encap with the Mirror SID).
4. **Egress NODE protection** — `make namespace pea ... down` (or stop zebra-rs in `pea`); within the BFD/hold-down window `ping from pe1 to <CE2 VPN prefix> should eventually succeed` (now via P1→PEB End.M→VRF→CE2). Assert the FIB on P1 switched to the backup.
5. **Teardown topology** — stop + delete all, assert clean.

### 5.2 SRv6 link protection — `bdd/tests/features/isis_mirror_sid_srv6_link.feature` (tag `@isis_mirror_sid_srv6link`)
Same topology; PEA is its own PLR. Take `pea`–`ce2` link down; assert PEA reroutes to PEB via Mirror SID and the VPN ping recovers. Teardown.

### 5.3 SR-MPLS node protection — `bdd/tests/features/isis_mirror_sid_mpls.feature` (tag `@isis_mirror_sid_mpls`) — Phase 8
Mirror of 5.1 with `segment-routing: mpls`, Binding TLV 149 + M-flag, context label, MPLS-VPN service. Assert `show isis database` carries the Binding TLV/M-flag, context-label ILM present (`ip -f mpls route`), and VPN ping survives PEA loss. Teardown.

### 5.4 Codec unit tests (Phase 1, not BDD)
`crates/isis-packet/tests/parser.rs`: round-trip the SRv6 Mirror SID sub-TLV (+ Protected Locators sub-sub-TLV) and the Binding TLV 149 with M-flag.

---

## 6. Risks & open questions

1. **Two-level seg6local decap.** Need to confirm the kernel will, within one packet, execute outer End.M (table M lookup) → inner End.DT46 (vrftable) when both localsids live on PEB. If a single seg6local can't chain, fold the inner step into table M as ordinary routes (the inner DA is PEA's End.DT46 SID re-instantiated locally). Validate early in Phase 4 with a hand-built `ip route`.
2. **SR-MPLS context label on Linux.** No per-context label table; the global-ILM approximation assumes PEA/PEB don't reuse the same VPN-label value for different VRFs. Acceptable for structured dual-homing/lab; documented. Real per-context needs eBPF/VPP (out of scope).
3. **Mirror SID allocation band.** Must not collide with End.X ELIB (`0xE000..` in `isis/srv6.rs`) or BGP End.DT46 (`0x0040..0xDFFF`). Pick/reserve a sub-band; add a compile-time invariant like `bgp/vrf/sid.rs` does.
4. **Stale-route retention vs. IS-IS hold-down gate.** The draft wants the PLR to *keep* the route to PEA after convergence so upstream keeps getting protection; our IS-IS hold-down gate may withdraw it. Reconcile timers in Phase 6/9.
5. **Protected-node identity in config.** system-id vs hostname vs locator-prefix — pick locator-prefix as the canonical key (it is what the sub-sub-TLV carries and what the draft keys on); allow hostname for convenience.
6. **ECMP.** TI-LFA skips ECMP destinations; the PLR repair to PEB should likewise handle (or explicitly skip) ECMP-to-PEA. Mirror the existing TI-LFA ECMP behavior.
7. **Scope guard.** Draft is single-area/level only and "modest service counts." Enforce/ warn, don't silently mis-protect across levels.

---

## 7. First cut — CONFIRMED 2026-06-20

- **Sequence:** SRv6 fully first (Phases 1a→7), SR-MPLS after (Phase 8). Rationale: SRv6 reuses End.DT6 dataplane with near-zero new kernel surface; SR-MPLS needs a new ILM type and carries a documented dataplane caveat.
- **MVP context FIB:** ship the static-config (`via-vrf`) population first so the first end-to-end BDD doesn't depend on the BGP-learned path; add BGP-learned context FIB immediately after as the production path.
- **PR granularity:** Phase 1a, 1b, 2, 3, 4, 5, 6, 7 each a separate PR/branch. ~8 PRs for SRv6, ~2-3 for SR-MPLS.

## 8. Progress log

- **Phase 1a — SRv6 codec — DONE** (branch `isis-mirror-sid-codec`, off `origin/main`). `crates/isis-packet/`:
  - `Behavior::EndM = 74` (`sub/srv6.rs`) — enum + both `From<u16>`/`Into<u16>` + `Display`.
  - `IsisPrefixCode::Srv6MirrorSid = 8` and `IsisSrv6MirrorSub2Code::ProtectedLocators = 1` (`sub/prefix_code.rs`) — note the Mirror-SID sub-sub-TLV registry is *separate* from the End-SID one so code 1 doesn't collide with `SidStructure`.
  - `IsisSubSrv6MirrorSid` (Flags+Behavior+SID+sub-sub-TLVs, layout mirrors `IsisSubSrv6EndSid`), `IsisSub2ProtectedLocators` (variable locator via `psize`/`ptakev6`), `IsisMirrorSub2Tlv` enum (`sub/prefix.rs`); wired into the prefix `IsisSubTlv` parse/emit/len + `prefix_disp.rs` Display + `sub/mod.rs` re-exports.
  - Round-trip test `srv6_mirror_sid_round_trips_through_isis_tlv` (`tests/parser.rs`). Gotcha pinned in the test: crate-root `IsisSubTlv` glob-resolves to `cap::IsisSubTlv` (Router Capability), so the SRv6 Locator sub-TLV must be named `prefix::IsisSubTlv`.
  - Green: `cargo test -p isis-packet` (52 tests), `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`. **Merged as PR #1478.**
- **Phase 2 — config + state — DONE** (branch `isis-mirror-sid-config`, off merged `main`). No dataplane; config is stored and parseable but nothing reads it yet (Phase 3 consumes it).
  - YANG: `container egress-protection { list protect { key protected-locator; leaf mirror-sid; leaf via-vrf; leaf dataplane {srv6|mpls}; } }` sibling of `fast-reroute` (`zebra-rs/yang/config.yang`).
  - New module `zebra-rs/src/isis/egress_protection.rs`: `MirrorDataplane` (FromStr, default Srv6), `MirrorProtect`, `MirrorProtectMap`, the four YANG callbacks (entry lifecycle + per-leaf), and `callback_register` — structured like `flex_algo.rs`. `Ipv6Net` can't derive `Default`, so `MirrorProtect::new(locator)` instead.
  - Wired: `IsisConfig::egress_protections` field + Default (`isis/config.rs`); `callback_register` call next to `flex_algo`/`affinity_map`; `pub mod egress_protection` (`isis/mod.rs`).
  - Tests: 4 state unit tests (`isis/egress_protection.rs`) + `isis_egress_protection_paths_parse` in `config::manager::yang_load_tests` (pins every settable path, since vtyctl apply is garbage-tolerant). Green: `cargo test -p zebra-rs egress_protection` (5), `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`.
- **Next:** Phase 3 — PEB SRv6 origination (allocate the Mirror SID from the locator, emit the sub-TLV in the self-LSP, `show isis egress-protection`).
