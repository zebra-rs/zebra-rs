# EVPN Multihoming: the dataplane problem, and whether cradle-rs solves it

*Analysis of "動いていると言えば動いている FRR の EVPN-Multihoming" (Kazuya Goda,
Sakura Internet, ENOG91 2026-08-28, `enog91_frr_evpn_mh.pdf`), mapped onto the
zebra-rs + cradle-rs architecture. Written 2026-08-28.*

---

## 0. Verdict in one paragraph

The ENOG91 talk's thesis is that FRR's EVPN-MH is complete in the control
plane but the Linux kernel gives it **no dataplane for the non-DF filter and
the split-horizon (SPH) filter**, so BUM duplicates and loops. Every workaround
the speaker had to build — SVD-only topology, a vlan-push eBPF program at
vxlan ingress to keep `ip_tunnel_info` alive, a tc-flower `l2_miss` pre-filter
because eBPF cannot read the bridge's miss verdict, a Lua→`os.execute`→C
control channel, an FRR patch to expose `sph_filters`, and the `br_netfilter`
incompatibility — is an artefact of **one fact: the bridge, the vxlan device
and the bond are opaque netdevs and per-packet context does not survive the
hop between them**. cradle-rs does not have that boundary: it decapsulates,
switches, classifies and replicates in one eBPF pipeline, so the source VTEP,
the bridge-domain and the FDB hit/miss verdict are all in hand at the exact
point where the DF and SPH decisions are made. **Moving the whole dataplane
into cradle-rs therefore resolves every *dataplane* problem in the deck by
construction.** It does **not** resolve the control-plane gaps the deck also
lists (HRW election, single-active E-LAN, aliasing/mass-withdraw consumers
— all still open in zebra-rs too), and it **introduces one problem the kernel
bridge solved for free: the LAG/LACP bundle that an Ethernet Segment is built
on**. Details, the full challenge inventory and the pros/cons follow.

**Decision (2026-08-28, maintainer): EVPN multihoming is cradle-only.** The
non-DF filter, split-horizon filter, ES nexthop group and single-active
enforcement will be implemented in the cradle-rs eBPF dataplane and driven
from zebra-rs over the existing gRPC tee. The kernel VXLAN backend (SVD,
`external vnifilter`) stays **single-homed**: zebra-rs will not replicate the
deck's tc/eBPF workarounds on the kernel bridge. Recorded in
`bgp-evpn-support-status.md`.

---

## 1. What the deck establishes

### 1.1 The five functions of EVPN-MH (slides 8–15)

| Function | Mechanism | Plane |
|---|---|---|
| Ethernet Segment (ES) | 10-byte ESI, advertised in Type-4; PEs sharing an ESI form the segment (a LAG spanning PEs, LACP toward the CE) | control |
| DF election + **non-DF filter** | one DF per ES (per EVI); non-DF **drops BUM toward the CE** | control + **data** |
| **Split-horizon (SPH) filter** | BUM received from a VTEP that belongs to the same ES is **not forwarded back to that ES** (VXLAN "local bias"; MPLS uses the ESI label) | control + **data** |
| Aliasing | remote PEs treat MACs behind an ES as reachable via *all* PEs that advertised A-D per ES/EVI → ECMP | control + data (NHG) |
| Mass withdraw | withdrawing the A-D per-ES route invalidates every MAC behind the ES in one message | control + data (NHG) |

### 1.2 FRR support matrix (slides 17–19)

| Item | FRR |
|---|---|
| Aliasing / Mass withdraw | supported — via Linux FDB nexthop groups (`bridge fdb … nhid`) |
| All-Active | supported |
| Single-Active | not supported |
| DF election | RFC 8584 preference only; RFC 7432 default (modulus) **not** supported |
| non-DF filter | **control plane only** |
| SPH filter | **control plane only** |

FRR issue [#15400](https://github.com/FRRouting/frr/issues/15400) ("EVPN-MH
split horizon filters not functional", FRR 9.1 / Linux 6.6) is still open with
label *triage — needs further investigation* and no maintainer answer. FRR's
`DPLANE_OP_BR_PORT_UPDATE` carries `non_df`, `sph_filters[]` and
`backup_nhg_id` to the dataplane provider; on mainline Linux only the
backup-nexthop half has a kernel counterpart (`IFLA_BRPORT_BACKUP_NHID`, 6.5).
The filters were meant for a vendor dataplane; on a plain Linux box they are
computed and thrown away.

### 1.3 The speaker's fix (slides 20–41), and what it had to fight

Architecture: FRR `on_rib_process_dplane_results` Lua hook → `os.execute
("/opt/ebpf/emfctrl df set|sph replace …")` → eBPF maps (`ifindex→non_df`;
map-in-map `ifindex→{(af,vtep)→1}`) consumed by two tc programs: a vxlan
**ingress** program and a bond **egress** filter (`evpn_mh_egress_filter`).

Three structural obstacles, each with a workaround:

1. **Source VTEP is gone at the bond egress.** The vxlan device has already
   decapsulated; the only carrier is skb tunnel metadata, which exists only in
   the SVD (`external vnifilter`) model and is **deleted when the vlan-aware
   bridge does its VNI→VID translation at egress enqueue** (slide 37). Fix:
   push the VLAN tag yourself at vxlan ingress (slide 38) so the bridge skips
   the translation and the metadata survives. This also mandates SVD (slide
   33) and **breaks under `br_netfilter`**, which strips the metadata (slide 43).
2. **eBPF cannot see `l2_miss`.** The bridge stamps its FDB-miss verdict in skb
   metadata with no BPF helper to read it (slide 40). Fix: a tc-flower rule
   `dst_mac 00:…/01:… l2_miss 0 action pass` at pref 1 so known unicast never
   reaches the BPF filter at pref 2. (`l2_miss` flower matching itself only
   exists since Linux 6.5 — it was added precisely for this non-DF use case.)
3. **FRR did not hand the SPH list to the hook** — only `sph_filter_cnt`
   (slides 25–26). Fix: a one-line FRR patch to marshal `sph_filters[]`.

The speaker's own closing assessment (slide 43): the cross-netdev skb
metadata lifetime is the sore point; an `l2miss` BPF helper is wanted; the
metadata deletion at the bridge→port boundary is "natural" for the kernel
model, which is exactly why it will not be fixed there.

---

## 2. Root cause: the netdev-boundary model

All three obstacles reduce to one property of the kernel L2 stack:

```
   vxlan netdev ──▶ bridge netdev ──▶ bond netdev ──▶ slave netdevs
   (decap; src    (FDB lookup;     (LAG hash;      (LACP in kernel)
    VTEP known)    l2miss known)    src VTEP gone,
                                    l2miss unreadable)
```

Each box is a separate `net_device` with its own `ndo_start_xmit`; the only
state that crosses a box is the skb itself, and skb metadata (`tunnel_info`,
`l2miss` bit in `skb->cb`-like fields) is owned by whichever layer allocated
it and freed whenever that layer is done. The decision points EVPN-MH needs
are at the **last** box; the information they need is produced at the
**first** two. Everything in slides 31–40 is smuggling information across
those boundaries.

What mainline Linux *does* provide for EVPN-MH, for the record:

| Kernel primitive | Since | Role in EVPN-MH |
|---|---|---|
| FDB nexthop groups (`bridge fdb … nhid`, `NDA_NH_ID`) | 5.9 | aliasing + mass withdraw (one NHG per ES) |
| SVD: `vxlan … external vnifilter` + `bridge vlan … tunnel_info` | 5.18 | single VTEP netdev for all VNIs; the only place tunnel metadata reaches the bridge |
| `IFLA_BRPORT_BACKUP_NHID` | 6.5 | fast failover when the local ES port goes down (redirect to the ES peers with the NHG attached) |
| tc-flower `l2_miss` match | 6.5 | the unknown-unicast half of the non-DF filter |
| non-DF drop | — | **none**: expected to be a tc rule that no daemon installs |
| SPH / local-bias drop | — | **none**: needs source-VTEP at bridge egress; not representable |

So the kernel has half of EVPN-MH (aliasing, failover) and has *pieces* of
the non-DF filter, but nobody integrates them, and the SPH filter is
structurally unrepresentable without the metadata hacks. That is the state
of the art the deck is titled after.

---

## 3. The complete challenge inventory

The deck covers the two filters. A full EVPN-MH implementation has to answer
all of the following; which plane each lives in decides whether "all the
dataplane in cradle" can help.

| # | Challenge | Plane | What it needs from the dataplane |
|---|---|---|---|
| C1 | ES object: port(s) ↔ ESI, per-EVI membership, redundancy mode | control | a port→ES binding the dataplane can consult |
| C2 | LAG toward the CE: LACP with a shared system-ID on both PEs (MC-LAG), or static LAG | **data** (kernel bonding today) | a bundle abstraction: member set, xmit hash, LACPDU handling |
| C3 | DF election: RFC 7432 modulus, RFC 8584 HRW + preference, AC-DF, peering/startup timers | control | nothing — only the result |
| C4 | non-DF filter | **data** | per-(egress port, BD): DF role; per-frame: BUM class incl. **unknown unicast** |
| C5 | SPH / local-bias filter | **data** | per-frame: **ingress VTEP** (VXLAN) or ESI label (MPLS); per-ES: the peer-VTEP set |
| C6 | Aliasing | control → data | MAC → ES → nexthop **group** of VTEPs, flow-hashed |
| C7 | Mass withdraw | control → data | update the ES NHG once, not per MAC |
| C8 | Fast local failover | data | local ES port down ⇒ frames for MACs learned on it go to the ES peers (kernel `backup_nhid`) |
| C9 | Single-active | control + data | non-DF blocks **all** traffic on the ES, not just BUM; receive side prefers the DF |
| C10 | MAC mobility × ES | control | same-ESI advertisements are mates, not moves (RFC 7432 §7.7/§8.4) |
| C11 | Local MAC → ES attribution | data → control | learning port reported upward; MAC/IP advertised with the ESI |
| C12 | Control→data channel | both | typed, transactional, replayable on daemon/engine restart; SPH list must be atomically replaced |
| C13 | Synchronisation between ES peers: ARP/ND and IGMP state (RFC 9251 Type-7/8), proxy-ARP | control | nothing |
| C14 | Observability | data | drop counters per reason (non-DF, SPH), per ES |
| C15 | Interop: MPLS ESI label (RFC 7432 §8.3), IOS-XR/Junos/Arista semantics | control + data | second-label inspection for MPLS |

The deck's three obstacles are C4, C5 and C12. The deck's "not supported"
rows are C3 (modulus/HRW) and C9.

---

## 4. Where zebra-rs and cradle-rs stand today

(From a code survey on 2026-08-28; file references are current `main`.)

### 4.1 zebra-rs — control plane rich, dataplane absent

| Item | Status | Evidence |
|---|---|---|
| ES config (Type-0 manual ESI, redundancy mode, one interface, DF preference, AC-DF bit, startup-delay) | ✅ | `yang/zebra-bgp-evpn.yang:208-296`, `bgp/config.rs:1891-2105`, `bgp/ethernet_segment.rs:100-126` |
| Type-4 ES, Type-1 A-D per ES (ESI-label EC), Type-1 A-D per EVI | ✅ originated | `bgp/route.rs:16968`, `:17034`, `:17082` |
| DF election: modulus (Alg 0) + preference (Alg 2), RFC 8584 negotiation | ✅ | `bgp/ethernet_segment.rs:215-280` |
| DF election: HRW (Alg 1) | ✅ `df-election algorithm hrw` (RFC 8584 §3) | `ethernet_segment.rs` `hrw_ranked` |
| Single-active backup path (RFC 7432 §14.1.1 pre-install) | ✅ SA `(ESI, EVI)` groups teed DF-first with `single_active`; cradle forwards to slot 0, backup slots promoted on the DF's per-ES A-D withdrawal | `route.rs` `evpn_es_nhg_sync`/`es_sa_primary`, cradle `ES_NHG_F_SINGLE_ACTIVE` |
| AC-DF behaviour (withdraw on AC down) | ✅ RFC 8584 §4: per-EVI candidate filter once every PE advertises it; an AC link-down withdraws the VPWS Type-1 / the port's per-EVI A-Ds; an ES port link-down withholds the ES routes | `route.rs` `es_ac_df_candidates`, `evpn_link_state` |
| Where the DF result goes | `show` and the VPWS P/B bits only | `bgp/show.rs:2565-2698`, `route.rs:17389-17422` |
| non-DF filter, SPH/local-bias | ❌ **nothing programmed anywhere** | `EvpnFloodState::desired` `route.rs:3046-3069` filters on P2MP/prune/AR only; zero `IFLA_BRPORT` in `fib/` |
| Aliasing consumer | ❌ modelled in RIB, first dest installed | `rib/inst.rs:5037-5052`, `MacEntry::installed_dest` `:901` |
| ES nexthop group in FIB | ❌ kernel `NDA_NH_ID` not used; cradle `FdbRemote` single-destination | `fib/netlink/handle.rs:3901-3908` (log line only) |
| Mass withdraw consumer | ✅ VPWS only | `route.rs:7819-7833` |
| Single-active | ✅ VPWS P/B only; ❌ E-LAN (ESI-label EC never parsed) | `as_esi_label` has no consumer |
| MAC mobility × ES | ✅ | `rib/inst.rs:869-897` |
| Local MAC → ES attribution | ✅ via learning port | `ethernet_segment.rs:44-58`, cradle `FdbEvent.port` |
| Kernel dataplane shape | SVD `external vnifilter`, vlan-aware bridge pinned to VLAN 1, no bond/LACP | `handle.rs:2827-2834`, `EVPN_SVD_VLAN=1` `:475` |
| BDD | 5 MH features, **all control-plane assertions, no ping** | `bgp_evpn_es`, `bgp_evpn_srv6_macip_multihoming`, `bgp_evpn_vpws_*` |

`docs/design/bgp-evpn-support-status.md:21` already states the sharpest gap:
*"MAC aliasing / mass-withdraw consumers — ❌ Open (receive side)"*.
`docs/design/bgp-evpn-ethernet-segment.md:208-223` lists DF-gated BUM,
local-bias SPH and aliasing as the unstarted "Phase 6 (dataplane)" and flags
the same kernel-primitive risk the deck ran into.

So: zebra-rs today is *exactly* FRR's position in slide 18 — "control plane
only" for both filters — minus FRR's kernel NHG aliasing.

### 4.2 cradle-rs — no MH concepts, but the right primitives

| Primitive | State | Evidence |
|---|---|---|
| Own FDB + learning + flood; **FDB miss is computed in the same program** that picks egress | ✅ | `l2_switch` `cradle-ebpf/src/main.rs:765-807`, `flood()` `:813-834` |
| B/M vs unknown-unicast distinction at `flood()` | ⚠️ computed then **discarded** (3 call sites pass only `from_overlay`) | `main.rs:786,795,805` |
| VXLAN decap in XDP; outer header in hand | ✅ | `try_vxlan_xdp` `main.rs:3948-4023` |
| Source VTEP carried to the switching stage | ❌ **discarded** at `adjust_head`; `CradleXdpMeta{magic,vrf_id}` is 8 bytes | `main.rs:4008`, `cradle-common/src/lib.rs:199-206` |
| Overlay split horizon (never re-flood into *any* overlay slot) | ✅ coarse, not ES-aware | `main.rs:827` |
| Per-member gate in the flood loop | seam exists; no per-member attributes today (`L2_MEMBERS` is a flat ifindex array, max 64) | `main.rs:825-829`, `:379` |
| Per-port flags | `PORT_F_L2/L3/ENDPOINT` only; `PORT_F_NO_FLOOD` is documented, **not implemented** | `lib.rs:790-795`; `docs/design/bgp-evpn.md:242` (aspirational) |
| ES / DF / ESI / SPH maps or RPC fields | ❌ none | `proto/cradle.proto` — `FdbRemote`, `ReplSlot`, `Port`, `L2Domain` carry no ESI/DF |
| Nexthop groups | ✅ for IP ECMP only (`NHGROUP`/`NHGROUP_MEMBER`); not reachable from the L2 path | `main.rs:177-180`, `ecmp_member` `:1733` |
| MAC → ES attribution upward | ✅ `FdbEvent.port` | `proto/cradle.proto:327`, `control.rs:3139-3148` |
| clsact **egress** program per port | ✅ exists (`cradle_egress`), but not used for L2 and lacks BD/class context | `main.rs:476-487` |
| LAG / bond / LACP | ❌ **nothing** | repo-wide grep; only a reserved-MAC punt *proposal* in `docs/design/l2-switching.md:199-202` |
| Kernel bridge in the path | no — by design; kernel `br`+`vxlan` exist in BDDs only as zebra's VNI anchor | `docs/design/bgp-evpn.md:28-31`, `cradle_evpn_vxlan_zebra.feature:56-64` |
| `br_netfilter` interaction | none (no kernel bridge) | — |
| Budget constraints | 448-byte stack wall in `cradle_tc`/`cradle_xdp`, no tail calls, 64 flood members | `main.rs:302-306`, `docs/design/tailcall-vs-monolithic.md` |

---

## 5. Does "all of the dataplane in cradle-rs" resolve the deck's issues?

Issue by issue, against the deck's own list:

| Deck issue | In cradle-rs | Resolved? |
|---|---|---|
| **SPH needs the source VTEP at egress; vxlan is already decapped** (slides 31, 35, 37) | Decap is cradle's own XDP stage. The outer IP is readable *before* `bpf_xdp_adjust_head`; widen `CradleXdpMeta` (8 → 24 bytes, well inside the 32-byte XDP meta area) with the ingress VTEP, or — cheaper — resolve `VTEP → ES-bitmap` at decap and carry a `u64`. Nothing between decap and `flood()` frees it: it is the same skb, the same program chain. | **Yes, by construction** |
| **SVD-only topology + vlan-push hack to keep `ip_tunnel_info`** (slides 33, 38) | No kernel vxlan/bridge in the path; VNI↔BD is cradle's own `VNI_INFO`/`VLAN_VNI` maps. No VID translation exists to lose metadata in. | **Yes** (problem does not exist) |
| **`br_netfilter` deletes the metadata** (slide 43) | No kernel bridge → no `br_netfilter` hook. | **Yes** |
| **eBPF cannot read `l2_miss`; tc-flower prefilter** (slide 40) | `l2_switch` *is* the FDB lookup; hit/miss is a local variable. `flood()` needs one extra parameter (`class: Bcast/Mcast/UnknownUnicast`) — a signature change, not a redesign. Bonus: the "forward unknown unicast on all PEs in all-active" nuance (slide 11) becomes a policy bit instead of a kernel accident. | **Yes** |
| **Control channel: Lua → `os.execute` → C → maps; FRR didn't expose `sph_filters`** (slides 23–28) | zebra-rs *is* the control plane and already drives cradle over typed gRPC with a `CradleMirror` that replays state on reconnect. New RPCs (`SetEs`, `SetEsRole`, `SetEsPeers`) are the same pattern as `SetVni`/`AddReplSlot`. Atomic SPH replace = a full-replace RPC, no map-in-map trick. | **Yes** |
| **non-DF filter** (slide 46) | A per-(port,BD) DF-role lookup in the `flood()` member loop (`main.rs:825-829`), next to the existing `REPL_SID` probe. Stack cost: one `u32` lookup per member. | **Yes** (small, contained change) |
| **Aliasing / mass withdraw** (FRR: kernel NHG) | cradle has no ES NHG for FDB entries. Needs `FDB_F_ESNHG` + an `ES_NHG_MEMBER` table consumed by the VXLAN/SRv6/MPLS encap, and zebra needs the receive-side consumer it lacks for *either* backend. Not solved by relocation; but cradle makes it uniform across the three encapsulations, while the kernel path would need `NDA_NH_ID` for VXLAN only. | **Not automatically** — new work on both sides |
| **DF election algorithms** (HRW; FRR lacks modulus) | Pure control plane. zebra-rs has modulus + preference, lacks HRW. | **No** — orthogonal to the dataplane |
| **Single-active** | Dataplane half is trivial in cradle (a "block everything" role bit); control-plane half (parse ESI-label EC, receive-side preference) is open in zebra-rs. | **Half** |
| **The ES is a LAG** (bond + LACP on every slide) | The kernel bridge got this for free from the bonding driver. cradle has no bundle abstraction, no LACPDU punt, and XDP-on-bond semantics (ingress ifindex = slave, redirect to the bond) are unhandled. | **No — this is the new problem cradle introduces** (see §6.3) |

**Net result:** the three *structural* obstacles that make the deck's approach
fragile (metadata across netdevs, `l2_miss`, the exec-based control channel)
disappear, because they are consequences of the kernel's netdev-boundary model
and cradle has no such boundary. What remains is honest feature work (ES NHG,
DF gate, SPH gate, control-plane consumers) plus one architectural debt —
LAG — that the kernel model hid.

---

## 6. Proposed architecture (zebra-rs control plane, cradle-rs dataplane)

### 6.1 Pipeline

```
                    zebra-rs (BGP EVPN)                           cradle-rs (eBPF)
  ┌───────────────────────────────────────────┐        ┌───────────────────────────────────────┐
  │ ES object ─ DF election ─ A-D per ES/EVI  │ gRPC   │ PORT_ES      ifindex → es_id           │
  │ Type-4 ─ ES peer VTEP set ─ MAC ⇄ ESI     │──────▶ │ ES_ROLE      (es_id, bd) → {DF, SA}    │
  │ FibHandle tee + CradleMirror (replayable) │        │ VTEP_ES      vtep → es-bitmap           │
  │                                           │◀────── │ ES_NHG       es_id → {vtep, nh}[]       │
  │  WatchFdb: learned MAC + port → ESI       │ stream │ FDB          (mac,bd) → oif | es nhg    │
  └───────────────────────────────────────────┘        └───────────────────────────────────────┘

  packet path (cradle):
   underlay ─▶ XDP: vxlan/srv6/mpls decap ─ meta{bd, ingress_es_bits} ─▶ TC l2_switch
              ─ FDB hit  → redirect(oif)            (or ES NHG member by flow hash = aliasing)
              ─ FDB miss / B / M → flood(bd, class, ingress_es_bits):
                   for member in L2_MEMBERS[bd]:
                     es = PORT_ES[member]?           # local ES port?
                     skip if es && ES_ROLE[es,bd] != DF && class ∈ BUM      # C4 non-DF filter
                     skip if es && (ingress_es_bits & bit(es))              # C5 SPH / local-bias
                     skip if es && ES_ROLE[es,bd].single_active && !DF      # C9
                     skip if member is an overlay slot && from_overlay      # existing
                     clone_redirect(member)
```

### 6.2 Control-plane additions (zebra-rs)

- **ES → cradle**: on ES create/port bind, `SetEs{es_id, ports[], redundancy}`;
  on every DF re-election, `SetEsRole{es_id, bd, df}` for each EVI the port is
  in (`RibRx::L2PortEvis` already enumerates them); on Type-4 changes,
  `SetEsPeers{es_id, vteps[]}` (full replace). Mirror all three in
  `CradleMirror` so an engine restart replays them before FDB/slots.
- **Aliasing consumer** (C6/C7): when a Type-2 with ESI ≠ 0 arrives, resolve
  the ES's live PE set from A-D per ES ∩ A-D per EVI, and install the MAC with
  `es_id` (`AddFdbRemote{…, es_id}`) instead of a single VTEP; on A-D per-ES
  withdraw, update `ES_NHG` once. This is the same consumer the kernel path
  would need for `NDA_NH_ID`; write it once in the RIB (`MacEntry.dests`
  already holds the set) and let each FIB backend render it.
- **AC-DF, HRW, single-active E-LAN** (C3/C9): independent of the dataplane
  choice; sequence after the filters.

### 6.3 The LAG problem (C2) — the one new cost

An ES is a LAG. With the kernel bridge, `bond0` (LACP, `ad_actor_system` set
to the same MAC on both PEs for MC-LAG) was just another bridge port. cradle
has to choose:

| Option | How | Pros | Cons |
|---|---|---|---|
| **A. Kernel bonding owns the LAG, cradle treats `bondN` as the port** (recommended first step) | attach XDP/TC to the bond; alias each slave's ifindex to the bond's `PortConfig` so `l2_switch` sees the slave ingress as the bond; `bpf_redirect(bond)` lets the bonding driver hash to a slave; punt reserved MACs (`01:80:c2:00:00:0x`, LACP/STP/LLDP) with `XDP_PASS` so the kernel LACP state machine keeps running | reuses LACP incl. `ad_actor_system` MC-LAG; small change; static LAG works trivially | native XDP on bond runs on slaves (kernel ≥ 5.15) with driver-dependent quirks — may need generic mode (cradle already has `CRADLE_XDP_MODE`); `FdbEntry.oif` must store the bond, not the slave |
| B. cradle-native bundle | member set + xmit hash in maps; LACP in userspace (zebra-rs or cradle) | no kernel bond, fully consistent model | LACP implementation is a project of its own; nothing exists today |

Option A keeps the deck's topology (`bond (LACP)` toward the CE) and is
BDD-able in netns (a Linux bond in the CE namespace, `ad_actor_system` on the
PE bonds).

### 6.4 Failover (C8) and single-active (C9)

- Local ES port down: zebra withdraws the local MACs (mass withdraw outward)
  and remote PEs re-point via aliasing. For the *local* side, mirror the
  kernel's `backup_nhid`: cradle marks the port down in `PORT_ES` and
  `l2_switch` treats FDB hits on a down ES port as "send to `ES_NHG` minus
  self" until aging/withdraw catches up.
- Single-active: `ES_ROLE.single_active && !DF` blocks all classes in
  `flood()` *and* in the unicast redirect path; receive side prefers the DF's
  Type-2 (needs the ESI-label EC consumer in zebra-rs).

### 6.5 Observability (C14)

Add `STAT_L2_DROP_NONDF`, `STAT_L2_DROP_SPH` and a per-ES counter map; surface
in `show ebpf`/`dump l2` and in `show bgp evpn ethernet-segment` next to the
DF line. The deck's demo had to prove filtering with `bpf_printk`.

### 6.6 Suggested sequencing (smallest PR first)

1. cradle: `flood()` gains `class`; `PORT_ES`/`ES_ROLE` maps; `SetEs`/`SetEsRole`
   RPCs; `STAT_L2_DROP_NONDF`. zebra: tee DF results. BDD: 2 PEs on one ES,
   dual-homed CE (plain two-port CE first, bond later), host behind PE2 pings
   → exactly one copy of each broadcast reaches the CE.
2. cradle: carry ingress VTEP/ES-bits in `CradleXdpMeta` (all three decaps);
   `VTEP_ES`; SPH gate; `SetEsPeers`. BDD: CE-originated broadcast is not
   echoed back by the peer PE (bounded counters, like `cradle_evpn_vxlan_multi`).
3. zebra RIB aliasing/mass-withdraw consumer + cradle `ES_NHG` (`FDB_F_ESNHG`);
   remote PE load-balances; A-D per-ES withdraw flips in one update.
4. LAG option A (bond as port, reserved-MAC punt, slave aliasing).
5. Single-active, backup-path, HRW, AC-DF.
6. MPLS: ESI label (second-label inspection below the service label) — only
   if MPLS-EVPN multihoming interop is required.

---

## 7. Pros and cons

### 7.1 Option comparison

| | **K: FRR/kernel + tc-eBPF add-on** (the deck) | **Z+C: zebra-rs control plane + cradle-rs dataplane** | **H: vendor ASIC (Cumulus/switchd, SONiC)** |
|---|---|---|---|
| non-DF filter | works with `l2_miss` flower + BPF, kernel ≥ 6.5 | native gate in `flood()` | native |
| SPH filter | works only with SVD + vlan-push hack; breaks with `br_netfilter` | native (source VTEP in meta) | native |
| Aliasing / mass withdraw | kernel FDB NHG (5.9), FRR wires it | new ES NHG in cradle + zebra consumer | native |
| LAG / LACP | kernel bonding, free | kernel bonding as a cradle port (option A) — new integration | native |
| Control channel | Lua→exec→C; not transactional, not replayed on restart; needed an FRR patch | typed gRPC + mirror replay | vendor SDK |
| Encapsulations | VXLAN only | VXLAN, SRv6 (End.DT2M/DT2U), MPLS — one gate for all. SRv6 proven end to end (BDD cradle-rs `cradle_evpn_mh_srv6`, `_zebra`; the split horizon needs the SRv6 outer source = the Type-4 Originating IP, which the tee now guarantees for an IPv6 `vtep-source`). MPLS proven end to end too (BDD `cradle_evpn_mh_mpls`, `_zebra`): split horizon by ESI label (RFC 7432 §8.3), allocated and advertised by zebra-rs, pushed only toward the segment's peers through per-(peer, segment) replication slots | vendor |
| Kernel version coupling | 6.5+ for `l2_miss`/`backup_nhid`; behaviour tied to bridge internals that upstream calls "natural" | eBPF/aya + verifier; BTF; no dependence on bridge internals | n/a |
| Performance | kernel bridge + 2 extra tc hops per BUM frame | XDP decap + TC switch, `clone_redirect` fan-out (≤ 64 members) | line rate |
| Debuggability | `bpf_printk`, `tc -s`, kernel drop reasons | cradle counters, `dump l2`, Hubble-style flow ring already exists | vendor |
| Footprint of change | ~zero to FRR (one patch), small eBPF | new maps/RPCs in cradle, consumer + tee in zebra | — |

### 7.2 Z+C — pros

1. **Solves the class of problem, not the instance.** Every future per-packet
   context need (ESI label for MPLS, per-VTEP AR roles, RFC 9572 gateway DF)
   has the same answer: put it in `CradleXdpMeta`. No more smuggling through
   VLAN tags.
2. **One decision point.** DF, SPH, single-active and the existing overlay
   split horizon are four conditions in one loop over the same member array;
   the deck spreads them over two tc hooks, a flower rule and the bridge.
3. **Control plane and dataplane are one project.** zebra-rs already knows the
   learning port (`FdbEvent.port`), the EVIs of a port (`L2PortEvis`), the DF
   result and the ES peer set; the tee and mirror-replay pattern is proven for
   VNI/FDB/repl slots. No Lua, no `os.execute`, no vtysh scraping.
4. **Uniform across VXLAN / SRv6 / MPLS.** The kernel can never do EVPN-MH for
   SRv6 or MPLS L2 (no L2 SRv6 decap into a bridge, no ESI-label inspection);
   cradle already carries all three L2 encapsulations through the same
   `l2_switch`/`flood()`.
5. **No SVD constraint, no `br_netfilter` landmine, no kernel-version cliff.**
   Works on the 6.8 LTS the BDD suite already targets.
6. **Testable end-to-end today** in the existing netns BDD harness (the deck's
   demo topology maps onto `cradle_evpn_vxlan_multi` + a dual-homed CE).
7. **Counters instead of `bpf_printk`** for the demo-critical "exactly one
   copy" proof.

### 7.3 Z+C — cons and risks

1. **LAG is not free anymore.** The kernel bridge inherited LACP MC-LAG from
   the bonding driver; cradle needs option A (bond-as-port + reserved-MAC
   punt + slave aliasing) before a real CE with LACP works. This is the
   largest single item and it is *not* in the deck because the kernel hid it.
2. **EVPN-MH becomes cradle-only.** zebra-rs keeps a kernel VXLAN backend
   (SVD, vlan 1) for hosts without cradle; that backend stays single-homed
   unless the deck's tc/eBPF approach is replicated there — which inherits all
   of its hacks. **Decided 2026-08-28**: *kernel backend = single-homed;
   multihoming requires `system ebpf enabled`* — recorded in
   `bgp-evpn-support-status.md`.
3. **Verifier and stack budget.** `cradle_tc` sits ~430 bytes into a 448-byte
   wall; the DF/SPH gates are map lookups (cheap) but the ES-NHG member
   selection in the encap path competes with the single `l2_overlay_encap`
   call site that already had to be de-duplicated to fit. Expect one round of
   stack surgery.
4. **Flood fan-out is `bpf_clone_redirect` per member, bounded at 64.** A
   large multihomed access layer (many ES ports + many VTEPs in one BD) hits
   the bound; the kernel bridge has no such limit. Raise or restructure
   (per-BD sub-lists) when needed.
5. **XDP-on-bond semantics** are driver- and kernel-dependent (native XDP
   propagates to slaves; some drivers only in generic mode). Budget for the
   `CRADLE_XDP_MODE=generic` fallback on bonded ports.
6. **Host-stack punts on L2 ports are incomplete** (IRB Phase 3 is
   design-only; ARP for an SVI is not punted). Not MH-specific, but a CE that
   needs a gateway on the PE hits it.
7. **No ASIC offload path** — software PE only. Matches the speaker's
   environment (software routers on servers) but not a hardware ToR.
8. **Control-plane gaps stay open regardless**: HRW (Alg 1), AC-DF behaviour,
   single-active E-LAN, the aliasing/mass-withdraw consumer, ESI types other
   than Type-0, ES-Import RT filtering. Relocating the dataplane does not
   shorten that list — it only stops it from being blocked on the kernel.
9. **Operational surface**: eBPF requires the aya nightly toolchain to build
   and `CAP_BPF`/`CAP_NET_ADMIN` at runtime; `bridge fdb show` no longer
   shows the truth (`cradle dump l2` does).

### 7.4 K (deck approach) — when it is still the right choice

- Hosts that must keep the kernel bridge (other consumers on `br0`,
  `br_netfilter`/nftables policies, hardware-offloaded vxlan NICs).
- Environments where a 6.5+ kernel is guaranteed and VXLAN is the only
  encapsulation.
- As a **parity fallback for zebra-rs's kernel backend**, if single-homed
  kernel mode is ever judged insufficient: it would be `NDA_NH_ID` FDB
  entries + tc-flower `l2_miss` + the vlan-push/SVD trick — precisely the
  deck, with its fragility.

---

## 8. Conclusion

The deck's title — "it works if you say it works" — is a statement about a
**dataplane whose building blocks cannot see each other**. Implementing the
whole dataplane in cradle-rs removes that blindness: source VTEP, bridge
domain and FDB verdict travel with the packet through one program chain, and
the DF and split-horizon decisions become two `if`s in the loop that already
performs ingress replication. So, to the question as asked: **yes, all of the
dataplane issues in the deck are resolved by construction** — including the
ones the speaker could only work around (metadata lifetime, `l2_miss`,
`br_netfilter`, SVD-only) — and cradle additionally brings EVPN-MH to SRv6 and
MPLS L2 where the kernel has no answer at all.

What it does **not** do is finish EVPN-MH. The control-plane consumers
(aliasing, mass withdraw for MACs, HRW, single-active E-LAN, AC-DF) are open
in zebra-rs exactly as they are open in FRR, and the ES-as-LAG problem that
the kernel bridge absorbed silently becomes cradle's to solve. The
recommendation — **adopted as the decision above** — is "multihoming is
cradle-only": ship the two filters first (they are the cheapest and the ones
with a live demo topology to prove against), then the ES nexthop group, then
LAG-as-bond, and record the kernel backend as single-homed rather than chase
the deck's workarounds there.

---

## References

- Deck: `enog91_frr_evpn_mh.pdf` (ENOG91, 2026-08-28, Kashiwazaki).
- FRR issue #15400 — <https://github.com/FRRouting/frr/issues/15400>.
- Speaker's implementation — <https://github.com/gokzy/frr-evpn-mh-filter>;
  FRR patch exposing `sph_filters` to Lua —
  <https://github.com/gokzy/frr/commit/dd149267dd829edf6eca40903ed38d06cfdadfde>.
- Linux FDB nexthop groups (Roopa Prabhu, net-next May 2020, Linux 5.9) —
  <https://lkml.kernel.org/netdev/1589854474-26854-3-git-send-email-roopa@cumulusnetworks.com/>.
- Linux bridge `backup_nhid` / tc-flower `l2_miss` (Linux 6.5) —
  <https://docs.kernel.org/networking/bridge.html>,
  <https://www.man7.org/linux/man-pages/man8/bridge.8.html>.
- RFC 7432 (BGP MPLS-Based EVPN) §8 multihoming; RFC 8365 §8.3 local bias;
  RFC 8584 (DF election framework: HRW, AC-DF).
- zebra-rs: `docs/design/bgp-evpn-ethernet-segment.md`,
  `docs/design/bgp-evpn-support-status.md`.
- cradle-rs: `docs/design/l2-switching.md`, `docs/design/evpn-vxlan.md`,
  `docs/design/bgp-evpn.md` (§Multihoming, Phase E),
  `docs/design/tailcall-vs-monolithic.md`.
