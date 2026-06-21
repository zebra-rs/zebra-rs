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
- **Phase 3 — PEB SRv6 origination + show — DONE** (branch `isis-mirror-sid-origination`, off merged `main`). Advertise-only; no dataplane/PLR yet.
  - `lsp.rs`: `mirror_sid_subs(&egress_protections, local_prefix)` emits one End.M sub-TLV per configured SRv6 entry whose explicit `mirror-sid` falls inside the node's own locator; added to the base SRv6 Locator TLV's sub-TLVs next to the End SID. Entries without an explicit SID, or with a SID outside the locator, are skipped (auto-allocation deferred).
  - `show isis egress-protection` (`exec.yang` leaf + `show.rs` renderer): lists each entry's protected-locator / mirror-sid / dataplane / via-vrf and an Advertised column computed with the same gate as the emit. The advertised sub-TLV is also visible in `show isis database detail` via the Phase-1a Display impl.
  - Book chapter `ch-07-08` updated with a Verification section + revised status.
  - Tests: `mirror_sid_subs_emits_only_in_locator_srv6_entries` (`lsp.rs`) + existing `exec_mode_loads` covers the new show grammar. Green: targeted `cargo test` (28), `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`. **Gotcha:** clippy `write_literal` on a `{}`+string-literal header arg — inline trailing literals into the format string.
- **Phase 4 — PEB SRv6 End.M dataplane — DONE** (branch `isis-mirror-sid-dataplane`, off merged `main`). The End.M localsid now installs; the mirror-context table stays empty until Phase 5.
  - `SidBehavior::EndM` (registry: enum + Display + FromStr + `prefix()` /128 arm). The "new SID variant needs a multi-site sweep": `fib/netlink/srv6.rs` (`seg6local_action` → `EndDt6`; `EndM` joins the `Table` branch), `fib/netlink/handle.rs` (route header = /128 main, like End.DT6/46). `sid_nexthop_uni` / `resolve_sid_ifindex` are behavior-generic — End.M falls in the loopback `_` arm like End.DT46, which is correct.
  - **End.M ≡ End.DT6 + `Table(MIRROR_CONTEXT_TABLE)`** — no native kernel action needed, exactly as scoped. `MIRROR_CONTEXT_TABLE = 0x4D000000`: a single shared mirror-context table per node (safe — protected service SIDs are globally-unique addresses; sidesteps per-node table allocation; high value avoids VRF/well-known table collisions).
  - `Isis::update_mirror_sids()` (del-then-add `SidAdd`/`SidDel`, gated identically to `lsp::mirror_sid_subs`) + `installed_mirror_sids` tracking. Hooked into the two `update_end_sid` sites (locator-watch reconcile + `process_sr_rx` resolution) and the egress-protection config callbacks (`reoriginate` now also reconciles the dataplane).
  - Tests: `end_m_decaps_via_mirror_context_table` (`fib/netlink/srv6.rs`) + `SidBehavior` round-trips cover EndM. Green: targeted `cargo test` (19), `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings` (real exit 0 — captured without the trailing-echo mask).
- **Phase 5 (static `via-vrf`) — mirror-context table population — DONE** (branch `isis-mirror-sid-context-fib`, off merged `main`). The decap now resolves into the CE VRF for the configured static path; BGP-learned population is a follow-up.
  - FIB (`fib/netlink/handle.rs`): `route_mirror_context_install/uninstall` — install an AF_INET6 route in an arbitrary table (`set_route_table` handles the >255 `MIRROR_CONTEXT_TABLE` via `RTA_TABLE`) for the protected locator with a `seg6local End.DT46 vrftable=<vrf>` encap.
  - RIB (`rib/inst.rs`): `Message::MirrorRouteAdd { prefix, context_table, vrf_name }` / `MirrorRouteDel`; `mirror_route_install` resolves `vrf_name` → kernel `table_id` (from `self.vrfs`) + the seg6 device, then calls the FIB. A not-yet-known VRF is skipped (next reconcile re-sends).
  - IS-IS (`isis/inst.rs`): `update_mirror_context_routes()` (del-then-add `MirrorRoute*`), `installed_mirror_routes` tracking, called next to `update_mirror_sids` at all three sites. Gate extracted to the pure `egress_protection::desired_context_routes` (same End.M gate + `via-vrf` set).
  - The route re-instantiates PEA's End.DT46 for the whole protected locator, so End.M's inner-DA lookup in the mirror table hits it → second decap into the CE VRF (the two-level decap; **kernel chaining is validated end-to-end in the Phase 7 BDD**).
  - Tests: `desired_context_routes_requires_in_locator_sid_and_via_vrf` (`isis/egress_protection.rs`). Green: targeted `cargo test` (7), `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`.
  - **Open:** VRF-appears-later — IS-IS only re-reconciles on config/locator change, not on `VrfAdd`; a `VrfAdd`-triggered reconcile is a follow-up (BDD sets the VRF up first).
- **Phase 6a — PLR reception + show — DONE** (branch `isis-mirror-sid-reception`, off merged `main`). Observability only; no repair install yet.
  - `egress_protection::collect_received_mirror_sids(&Lsdb)` scans the LSDB for SRv6 Mirror SID sub-TLVs and returns `ReceivedMirrorSid { protector, mirror_sid, protected_locator }`. Pure per-LSP extractor `mirror_sids_from_tlvs` underneath (unit-tested). Deliberately a standalone scan rather than threading the 16-site `SysStateRefs` machinery — Mirror-SID reception isn't a core consumer map, and the show path can compute it on demand.
  - `show isis egress-protection` now has two sections: **Local egress-protection** (configured, with the Advertised column) and **Received Mirror SIDs** (protector / mirror-sid / protected-locator, scanned from both levels). The empty early-return was removed so a PLR with no local config still shows what it received.
  - Tests: `mirror_sids_from_tlvs_extracts_protector_and_protected_locator` (`isis/egress_protection.rs`). Green: targeted `cargo test` (7), `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings` (real exit 0). **Gotcha:** `clippy::to_string_in_format_args` fires on a plain `{}` arg (not on width-specified `{:<N}` ones) — drop `.to_string()` there.
- **Phase 6b — PLR repair install — DONE** (branch `isis-mirror-sid-plr-repair`, off merged `main`). The PLR now installs the backup; with Phases 1a–6a this is the first end-to-end *functional* slice (pending BDD validation).
  - `inject_mirror_sid_backups` runs in `apply_spf_result` (main thread, live LSDB) right after the v6 RIB is built — no SPF-offload snapshot plumbing. For each received Mirror SID it sets, on the route to the **protected** locator, a backup `RepairPathSrv6 { segs:[mirror_sid], encap:HEncap, (addr,ifindex) }` where `(addr,ifindex)` = the primary nexthop of the route covering `mirror_sid` (the **protector's** locator, via `nexthop_toward_protector` = `PrefixMap::get_lpm`). Skips a nexthop that already has a TI-LFA backup (transit protection wins).
  - The existing generic `SpfNexthop.backup` → `make_rib_entry` → `Nexthop::Protect` machinery turns it into a primary/backup pair; **the BFD `protect_switch` trigger is free** — it keys on the primary nexthop address, which is the protected egress's adjacency address when the PLR neighbors it (the canonical node-protection topology). No new trigger code.
  - Tests: `apply_mirror_sid_backups_hencaps_to_protector` (`isis/rib.rs`, pure core factored out of the LSDB scan). Green: targeted `cargo test`, `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`. **Gotcha:** the `EncapType` import was `#[cfg(test)]`-gated (only the backup test fixture used it); production use needed an ungated import.
  - **Open / limitations:** the H.Encaps repair is a single segment `[mirror_sid]` — it assumes the protector is reachable on a path not through the failed egress (true for dual-homing); no TI-LFA-style repair-list-to-protector is computed. PE–CE link protection (PEA as its own PLR) not yet wired.
- **Phase 7a — control + install BDD — DONE & GREEN on real namespaces** (branch `isis-mirror-sid-bdd`, off merged `main`). 5 scenarios, 46/46 steps pass.
  - `bdd/tests/features/isis_mirror_sid_srv6.feature` (tag `@mirror_sid_srv6`) + 4 configs (`pe1`/`p1`/`pea`/`peb`): a 4-router IS-IS-L2 SRv6 topology where `peb` protects `pea`'s locator. Validates **advertisement** (`show isis egress-protection` advertised=yes, `show isis database detail` carries the End.M sub-TLV), **reception** (`p1` Received section), the **End.M localsid install** (`show segment-routing srv6 sid` + `ip -6 route` seg6local), and the **PLR backup install** (`show isis route detail` on `p1` carries the protected locator + Mirror SID). No BGP/VRF needed for this slice.
  - **The run found and fixed two real bugs the unit tests couldn't:**
    1. **Kernel-dataplane fix (`rib/inst.rs resolve_sid_ifindex`):** the Linux kernel *silently strips a seg6local encap whose oif is `lo`* (verified on 6.8: `End.DT6 dev lo` installs as a plain route; `dev sr0` keeps the encap). End.M was resolving to `lo` (the `_` arm) → no decap installed. Fix: End.M joins the `sr0` group with End/uN/EndDT4/EndDT6. **This is a genuine implementation bug in the Phase 4 dataplane that only a live run surfaced** — the unit test asserted the *attrs* were built, not that the kernel *kept* them.
    2. **Config:** a bare-`::`-terminated IPv6 scalar (`mirror-sid: fcbb:bbbb:4:1::`) trips the YAML scanner; must be quoted.
  - **Reminder:** BDD is excluded from PR CI gates, so this green is from a local run (`sudo` cucumber against the installed debug binary), not CI.
- **Phase 7b foundation — VRF VPNv4/VPNv6-over-SRv6 forwarding — DONE & GREEN on real namespaces** (branch `isis-mirror-sid-bdd-traffic`, off merged `main`). Before the failover BDD can ride a real BGP L3VPN service, that service has to actually *forward* — and VRF L3VPN-over-SRv6 (End.DT46) had **no traffic BDD at all** and was silently black-holing. A 2-PE diag (z1/z2, IS-IS-L2 SRv6 + iBGP VPNv4/VPNv6 + dual-stack VRF) traced it end-to-end. **Four real bugs, all fixed; `bdd/tests/features/mirror_sid_vpnsrv6_base.feature` (tag `@mirror_sid_vpnsrv6_base`) reliably green 3/3, both AFIs 0% loss:**
  1. **Egress End.DT46 on `lo`** (`rib/inst.rs resolve_sid_ifindex`) — the *same* kernel-strips-seg6local-encap-on-`lo` bug Phase 7a hit for End.M, but the BGP per-VRF End.DT46 service SID was still in the `_`/`lo` arm. Added `EndDT46` to the `sr0` group → all SRv6 L3VPN egress decap was dead before this. (The Phase 4 entry above claimed "End.M falls in the loopback `_` arm like End.DT46, which is correct" — the End.DT46 half of that was wrong; only the BGP L3VPN traffic path exercises it, which had no BDD until now.)
  2. **VPNv6 next-hop not stamped** (`bgp/route.rs route_ipv6_update`) — the MP_REACH next-hop arrives via the `nexthop` param but is never folded into `attr.nexthop` (v6-unicast and VPNv4 stamp it); `bgp_nexthop_ip`=None → NHT never tracks the PE locator → empty transport → no ingress H.Encap. Stamp `BgpNexthop::Vpnv6`.
  3. **rp_filter** (`fib/netlink/sysctl.rs`) — End.DT46 re-injects the decapped inner-v4 on `sr0`, asymmetric to its src's H.Encap return path → strict reverse-path filtering drops it (v6 has no RPF, so it worked, hiding the v4 break). zebra-rs set `ip_forward` but not rp_filter; added `net.ipv4.conf.{all,default}.rp_filter=0`.
  4. **VPNv6 export-RT race** (`bgp/inst.rs`) — THE intermittency cause. A per-VRF route originated into `v6vpn` *before* its `VrfRouteTargets` lands is advertised with **no export RT** → the remote PE's `import_targets_v6` finds no match and silently drops it (no re-advertise re-triggers). VPNv4 already closes this via `retag_vrf_exports_v4` on `export_v4_changed`; v6 had no equivalent and didn't even track `export_v6_changed`. Added `retag_vrf_exports_v6` (mirror: re-tag this VRF's originated `v6vpn` rows via `shard.update_v6vpn` + `route_advertise_to_peers_vpnv6`) + the wiring. Traced precisely: `dispatch_import_v6 n_matches=0 has_ecom=false` with the VRF fully ready — an *egress* RT-tagging gap, not the import-side `route_sync_vpnv6` first suspected.
  - Also: book `ch-02-05` ("L3VPN over an SRv6 Underlay") config example made explicitly dual-stack (one End.DT46 SID terminates both AFIs). 505 bgp unit tests pass; `cargo fmt` + `cargo clippy --workspace --all-targets` clean. **BDD excluded from CI — green is a local `sudo` cucumber run.**
- **Phase 7b proper — SRv6 egress LINK protection, live failover — DONE & GREEN on real namespaces** (branch `isis-mirror-sid-failover`, off merged `main`; two commits: steady-state baseline + redirect mechanism). The milestone chose **egress link protection** over node protection: with node protection (kill PEA) the *ingress's* BGP reconverges to PEB within seconds, so steady-state traffic rides the BGP backup, not the Mirror SID — the test would go green for the wrong reason; and `protect_switch` fires only on BFD-down and the switched route doesn't survive SPF reconvergence (stale-route retention, Risk #4, is unbuilt). Egress link protection keeps PEA fully alive (IS-IS/BGP stable, no ingress churn), so the Mirror SID **provably and durably** carries the traffic.
  - **Topology** (`@mirror_sid_egress_link`, 5 ns: ce1/pe1/pea/peb/ce2): dual-homed CE2 (loopback reached on both pea and peb via **router-static-vrf**), pe1 ingress + iBGP VPNv6 full-mesh, pea sole BGP advertiser of CE2 (so pe1 deterministically forwards via pea's End.DT46 SID), peb pure protector (Mirror SID + `via-vrf` mirror-context). CE2 returns to CE1 via peb in both states, so only the forward path changes on failover.
  - **Mechanism (PEA as its own PLR).** IS-IS pushes every received `(protected_locator, mirror_sid)` to the RIB each SPF (`register_egress_protections`); the RIB matches a locator against its *own* End.DT46 service SIDs. On PE-CE link down the RIB re-encapsulates that SID toward the Mirror SID. **The redirect is a route-level seg6 H.Encaps (`route_sid_redirect_install`, NLM_F_REPLACE), NOT `End.B6.Encaps`:** the inbound H.Encap arrives with `segleft=0`, which the seg6local endpoint action rejects (kernel `get_and_validate_srh` needs `segleft>=1`) and silently drops; a route-level encap on the now-non-local SID forwards + encapsulates correctly. PEB's End.M (End.DT6→mirror-context) then End.DT46→VRF delivers — the two-level decap, validated with live traffic (0% loss).
  - **Robustness.** `vrf_can_deliver` gates on the CE-facing VRF having an up, addressed member link. The redirect is **latched**: restored only when the link recovers, never when a transiently-partial LSDB scan (the link-down-triggered SPF momentarily reads the live LSDB as 1 LSP) clears the registration; `egress_protect` is also kept **sticky** (an empty scan never drops the last-known protector — PIC-like). `vrf_add` re-runs the mirror-context reconcile (Phase 5 VRF-appears-later follow-up) so the `via-vrf` route installs once the netlink VRF table appears.
  - **Test gotcha:** downing a VRF-enslaved interface intermittently triggers a kernel flush race (pea-ce2 flaps down→up ~7ms later); settle `wait`s after the link change + `ping … eventually succeed` make the scenario reliably green while usually exercising the genuine redirect. 6 scenarios / 56 steps green. **BDD excluded from CI — green is a local `sudo` cucumber run.**
- **Phase 8 (SR-MPLS variant) — IN PROGRESS, sliced.** Carries Risk #2 (Linux has no per-context label table; the dataplane uses a global-ILM approximation valid for structured dual-homing/lab, documented).
  - **Slice 1b — codec — DONE** (branch `isis-mirror-sid-mpls-codec`, merged PR #1541). RFC 8667 §2.4 SID/Label Binding TLV (149) with the M-flag in `crates/isis-packet`: `IsisTlvSidLabelBinding { flags: BindingFlags, weight, range, prefix: BindingPrefix(V4/V6), subs }`, `IsisBindingSubTlv` (SID/Label sub-TLV = context label; everything else round-trips as raw). Display surfaces "SID/Label Binding (Mirror Context)". Two round-trip tests. Pure codec, no behavioral change.
  - **Slice 1 — origination + reception + show — DONE** (branch `isis-mirror-sid-mpls-origination`, control-plane only). PEB allocates one **context label** per `dataplane: mpls` egress-protection entry from the SRLB `local_pool` (`Isis::mirror_labels`, stable across LSP regens, released on config removal; reconciled by `update_mirror_labels` at the config/SR-block/locator sites). `lsp::mirror_binding_tlvs` emits a top-level Binding TLV (149) with M-flag, the protected loopback as the IPv6 FEC, and the context label in a SID/Label sub-TLV. The PLR side scans the LSDB via `collect_received_mpls_bindings` → `ReceivedMplsBinding { protector, context_label, protected_fec }`. `show isis egress-protection` gains the context-label column + a "Received Mirror Context labels" section. Origination + reception unit tests. **Note:** the context label reuses the SRLB rather than a separate band (it is the node's local-SID block; the ILM in slice 2 distinguishes context labels by entry type) — a deliberate, simpler deviation from the plan's "separate pool". No live BDD yet — the SR-MPLS topology is built with slice 4.
  - **Slice 2 — context-label ILM dataplane — DONE** (branch `isis-mirror-sid-mpls-ilm`, control-plane install; live validation with slice 4). `IlmType::ContextLabel { table_id, vrf_ifindex }` — **netlink-identical to the proven `DecapVrf`** (pop + `Oif(vrf)` so the inner packet lands in the VRF table). The protector installs one ILM decap per `dataplane: mpls` entry with an allocated label + a `via-vrf` resolved to its kernel ifindex (`update_mirror_context_labels` → `desired_context_labels` pure core; reconciled at the config/SR-block/locator sites and on `VrfAdd` for the via-vrf-appears-later race). **Key design choice:** adopting the egress-LINK-protection model (consistent with Phase 7b — the protected egress redirects and strips its own VPN label) means the protector only ever pops *one* label, so `DecapVrf` semantics suffice and the uncertain two-label node-protection pop (which needs the Linux global-ILM approximation, Risk #2) is sidestepped/deferred. `show mpls ilm` renders "Mirror Ctx". Pure-core unit test.
  - **Slices 3 + 4 — egress redirect + live dual-homing failover — DONE** (branch `isis-mirror-sid-mpls-failover`, off merged `main`; **6/6 BDD scenarios green on real namespaces**). The egress redirect is the SR-MPLS analog of the SRv6 End.B6.Encaps redirect, with the same latch-on-link-state discipline:
    - **Config v4 extension (prerequisite).** SR-MPLS transport is IPv4 (IS-IS has no IPv6 prefix-SID — `rib.rs:251` "deferred until SRv6 IS-IS lands"), so the protected egress is identified by its **IPv4** loopback. `protected-locator` YANG widened `inet:ipv6-prefix → inet:ip-prefix`; `MirrorProtect.protected_locator`/`MirrorProtectMap`/`mirror_labels`/`ReceivedMplsBinding.protected_fec` moved `Ipv6Net → IpNet`; `mirror_binding_tlvs` emits the FEC family from the locator (v4 ⇒ F-flag clear); SRv6 paths extract the V6 locator (still IPv6).
    - **IS-IS side (`register_mpls_protections`, run each SPF).** The protected egress detects it is protected when a received Mirror Context binding's FEC covers its own `te-router-id`; the protector (carried only as a sys-id) is resolved to its loopback via `node_te_router_id` (TE Router-ID TLV 134 in the protector's LSP). Sends `Message::EgressMplsProtectSet { (context_label, protector_loopback) }` (sticky, like the SRv6 registration).
    - **RIB side.** On PE-CE link down (`vrf_can_deliver` false), `apply_egress_mpls_redirect` finds the BGP `DecapVrf` VPN-label ILM in the **main RIB `self.ilm`** (confirmed present — the `ilm_show` decap-row fix surfaced it) and **replaces** it (new `FibHandle::ilm_replace`, `NLM_F_REPLACE`) with a swap pushing `[transport…, context_label]` toward the protector. Transport resolved by LPM on the protector loopback (`resolve_protector_transport_v4`); empty under PHP for an adjacent protector (so the swap is just `[context_label]`). Latched: restored to `DecapVrf` only when the VRF can deliver again. Hooked into `link_down`/`link_up` next to the SRv6 reconcile.
    - **Two non-obvious fixes during live bring-up:** (1) `ilm_add` is `CREATE|EXCL`, so the swap EEXIST'd over the existing per-label DecapVrf route — needed `NLM_F_REPLACE` (one kernel route per label). (2) the installed YANG silently reverted to `ipv6-prefix` (parallel-worktree stomp of `/etc/zebra-rs/yang`) — re-install YANG, not just the binary, before every BDD run.
    - **BDD `@mirror_sid_mpls`** (`pe1`/`pea`/`peb` + `ce1`/`ce2`, all v4): IS-IS SR-MPLS + iBGP VPNv4 converge; steady-state ce1↔ce2 forwards via pea; peb advertises the binding + installs the "Mirror Ctx" ILM; pea installs "VPN Decap"; then PE-CE link down → ping recovers via the context label, link up → `DecapVrf` restored → ping recovers. This is the **first end-to-end live SR-MPLS slice**; the control plane (1/1b/2) is now validated by forwarding, not just show output.
- **Phase 9 hardening** — node-protection stale-route retention (Risk #4), a proper egress-protection *withdrawal* path (clear `egress_protect` when the protector's LSP is present but drops the Mirror SID, rather than only sticky-keep), and `show` surfacing of the redirected (B6/H.Encaps) form (today `show segment-routing srv6 sid` keeps showing the canonical End.DT46; the kernel route reflects the live redirect).
