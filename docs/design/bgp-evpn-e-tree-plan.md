# EVPN E-Tree — Design & Phasing Plan (RFC 8317 · draft-ietf-bess-rfc8317bis)

Making an E-LAN a **rooted-multipoint** service: every attachment circuit
(AC) is a *root* or a *leaf*, roots reach everyone, and **a leaf never
reaches another leaf** — not on the same PE, not across the core, not for
known unicast and not for BUM.

Nothing of E-Tree exists in zebra-rs or cradle today (no codec, no config,
no datapath; checked 2026-10-14 against main `140126e6` and cradle
`e6fab55`). What does exist is most of the machinery it is built from:
per-port Ethernet Segment state, the ESI-label split-horizon path, the
per-MAC FDB, and the service-label allocator. This plan maps RFC 8317 onto
those pieces and orders the work smallest-first.

Read together with:
- [`bgp-evpn-support-status.md`](bgp-evpn-support-status.md) — the
  per-encapsulation matrix this feature will add a row to.
- [`bgp-evpn-multihoming-dataplane.md`](bgp-evpn-multihoming-dataplane.md) —
  why multihoming forwarding is cradle-only; E-Tree lands on the same side
  of that line (§8.1).
- [`mpls-label-allocation.md`](mpls-label-allocation.md) §5.2 — the service
  label chunks the per-PE leaf label is drawn from.
- [`bgp-evpn-single-active-plan.md`](bgp-evpn-single-active-plan.md) — the
  shape this plan follows, and the source of the review lessons in §10.
- cradle-rs `docs/design/bgp-evpn.md` §Multihoming — the datapath side.

Branches: `evpn-e-tree-design` (this document, #2519), `evpn-e-tree`
(phase 1, #2521; phase 2b). Phase 2a is cradle-rs #204, released in
cradle-rs v1.1.4.

## 1. What E-Tree means, and which flavour we build

RFC 7387 / MEF 6.1 define the service; RFC 8317 defines it for EVPN. The
permitted flows (RFC 8317 §4.3):

| From \ To | Root | Leaf |
| --------- | ---- | ---- |
| **Root**  | ✅ unicast + BUM | ✅ unicast + BUM |
| **Leaf**  | ✅ unicast + BUM | ❌ **never** |

RFC 8317 §3 sorts deployments by where the root/leaf boundary falls:

| Scenario | Role granularity | How RFC 8317 handles it | This plan |
| -------- | ---------------- | ----------------------- | --------- |
| 1 | per **PE** (an EVI on a PE is all-root or all-leaf) | two RTs per EVI (approach A), *or* approach B below | covered by approach B — a PE whose ACs are all leaves is just scenario 2 with no root AC |
| 2 | per **AC** (one EVI on a PE mixes root and leaf ACs) | **approach B**: one RT per EVI, MACs coloured by the E-Tree extended community | ✅ **build this** |
| 3 | per **MAC** on one AC | known unicast only; BUM is dropped at the ingress PE | ❌ out of scope — rfc8317bis §4.3 itself notes no application has been identified, and BUM cannot be supported |

Approach B is what RFC 8317 recommends "across all the above three
scenarios" (§3.3) and what every vendor surveyed in §2 ships. Approach A
(Leaf-RT / Root-RT import policies) needs no E-Tree code at all — it is RT
configuration — and is not automated here.

### 1.1 Scope and acceptance

**In scope:** E-LAN, ingress replication, the cradle datapath, single-homed
and multihomed (all-active and single-active) ACs. Known-unicast filtering
for **all three** encapsulations (VXLAN, MPLS, SRv6), because it is purely a
control-plane colouring of Type-2 routes; BUM filtering per encapsulation in
the order the standards are settled: **MPLS** (RFC 8317, standards track),
then **VXLAN** (no standard — decision D2), then **SRv6** (needs Arg.FE2 in
cradle first).

**Explicitly not claimed:**

- **The Linux-kernel backend.** The kernel bridge has no per-MAC leaf drop
  and no leaf label; it can isolate leaf ports locally and nothing more
  (§8.1). E-Tree enforcement is cradle-only, as multihoming already is.
- **P2MP P-tunnels and the composite tunnel type** (RFC 8317 §6.2). zebra-rs
  originates SR-P2MP IMETs for other features; an E-Tree BD stays on
  ingress replication (§4.3).
- **Assisted replication** (RFC 9574) on an E-Tree BD: an AR-REPLICATOR does
  not know the copy's origin role. Not combined.
- **IRB.** RFC 8317 §4.2.3 puts IRB out of scope, and for a reason that
  matters operationally: a BD with an SVI / anycast gateway lets two leaves
  talk *through L3*. E-Tree is an L2 property. `show` warns (§9); nothing
  blocks routed traffic.
- **VPWS / E-Line.** E-Tree is an E-LAN service.

## 2. The standards picture

What is settled, what is drafted, and what is merely deployed:

| Document | Status | What it gives us |
| -------- | ------ | ---------------- |
| **RFC 8317** (2018) | Standards Track | The E-Tree EC (EVPN sub-type `0x05`) with the Leaf-Indication flag; Type-2 colouring for known unicast (§4.1); the per-PE **leaf label** on an EAD-ES route with **ESI 0** for MPLS BUM egress filtering (§4.2); the composite PMSI tunnel bit (§6.2). MPLS only. |
| **RFC 9252** §6.3 | Standards Track | One sentence that matters: for E-Tree, the ESI filtering argument (**Arg.FE2**) of the SID on the Route Type 1 is OR-ed into the remote End.DT2M SID, "details … in [RFC8317]". |
| **draft-ietf-bess-rfc8317bis-00** (2025-10) | WG document, **expired 2026-04** | Adds §5.3 VXLAN/GENEVE BUM via a second **leaf VNI** carried in the E-Tree EC on the IMET; §5.4 SRv6 via Arg.FE2 on the ESI-0 EAD-ES (encoding deferred to draft-ietf-bess-bgp-srv6-args, now RFC 9819); §5.6 *adaptive* ingress/egress filtering with a new **Root-Indication** flag (bit 6). |
| **RFC 9819** (2025-07, was draft-ietf-bess-bgp-srv6-args) | Standards Track, updates RFC 9252 | Replaces RFC 9252's bitwise OR of Arg.FE2 into the End.DT2M SID with explicit placement at offset LBL+LNL+FL; the IMET and the A-D route must signal the same argument length (§8.6). |
| **draft-bamberger-bess-imet-filter-evpn-etree-vxlan-00** (2023, Arista) | Individual, **expired** | VXLAN BUM by *flood-list pruning*: a leaf PE puts the E-Tree EC (L=1, label 0) on its IMET; a leaf PE receiving it leaves the sender out of its flood list. No datapath tag. |

The two VXLAN proposals are **not wire-compatible**: rfc8317bis requires a
valid (non-zero) leaf VNI in an IMET's E-Tree EC and discards an IMET whose
leaf VNI does not match its own, while the Arista draft sends label 0. §8.5
works through the consequence.

Vendor landscape — **from vendor documentation, not verified in a lab**:

| Implementation | E-Tree support documented |
| -------------- | ------------------------- |
| Nokia SR OS | EVPN-MPLS E-Tree: `leaf-ac` SAPs, leaf label on an "AD per-ES per-PE" route |
| Juniper MX (Junos) | EVPN-MPLS E-Tree only (`etree-ac-role`) |
| Arista EOS | E-Tree EC on Type-2 **and Type-3**, VXLAN only; MPLS via asymmetric RTs (approach A) |
| FRR | none — its EVPN documentation does not list RFC 8317 |
| Cisco IOS XR | not verified |

So there is **no FRR interop partner** for any of this: the interop lab
(phase 6) needs Arista cEOS for VXLAN and a Nokia or Juniper image for MPLS.

## 3. What is already on main (do not re-derive)

References are to main `140126e6` (zebra-rs) and `e6fab55` (cradle-rs).

| Building block | Where |
| -------------- | ----- |
| EVPN EC codec: private sub-type consts `0x01` ESI Label, `0x02` ES-Import, `0x03` Router's MAC, `0x04` L2-Attr, `0x06` DF Election, `0x09` Mcast Flags, `0x0F` SCT — **`0x05` unused** | `crates/bgp-packet/src/attrs/ext_com.rs:420-446` |
| Unknown EVPN sub-types are parsed, stored, re-advertised unchanged, and shown as `unknown:<ip>:<n>` | `ext_com.rs:41-58` (parse), `:1017-1025` (Display) |
| Type-2 origination knows the learning port: `FdbEntry.ifindex`; ESI resolved per MAC at origination | `bgp/route.rs:19747` `evpn_originate_macip`, `:20083` `macip_esi`; `rib/api.rs:64` |
| Re-originate every cached local MAC when an attribute changes | `route.rs:20112` `evpn_resync_macip_esi` |
| Per-ES A-D origination (RD `<rid>:0`, eth-tag MAX-ET, ESI Label EC) | `route.rs:20599` `evpn_originate_ethernet_ad_es`; generic `evpn_originate_synch` `:22917` |
| A received per-ES A-D with **ESI 0** is stored, best-path selected, reflected — and ignored by every consumer | export arm `route.rs:~10541`; `evpn_es_nhg_sync` skips `ZERO_ESI` `:21514` |
| Peer ESI labels for split horizon | `route.rs:9777` `es_peer_esi_labels`; `evpn_es_df_sync` `:21919` |
| Service-label allocator (chunks from the RIB label space) | `Bgp::service_labels` `bgp/inst.rs:1247`; `label_chunks.rs:103` `alloc`, `:170` `free` |
| The ESI label lifecycle — the template for a per-PE leaf label | `inst.rs:5837` `es_label_reconcile`, `:5923` `es_esi_label`, `:5683` `service_labels_reconcile` |
| Per-MAC flags on a remote MAC (sticky/gateway/router) | `rib/evpn.rs:34` `MacRoute.flags`; `route.rs:9636` `extract_flags_from_attr` |
| Which EVIs a bridge port belongs to | `inst.rs:5904` `Bgp::port_evis` |
| Encapsulation is **one global** setting | `zebra-bgp-evpn.yang:158`; `Bgp::evpn_encap` `inst.rs:1291` |
| cradle switches local ports itself (no kernel bridge in the forwarding path) | cradle `crates/cradle-ebpf/src/main.rs:882-901` (unicast), `:998` `flood` |
| cradle per-port state: `PORTS` (one BD per port), `PORT_ES`, `ES_DF`, `ESI_LABEL`, `SLOT_ES` | cradle `main.rs:82,243,247,273,280` |
| cradle MPLS: one extra label under the service label on transmit; on receive exactly one, which must be in `ESI_LABEL` or the frame is **dropped** | cradle `main.rs:3813` `l2_mpls_encap`, `:5348` `pop_decap_l2` |
| cradle FDB: `FdbEntry{oif, flags, remote_sid, last_seen, label}`, flag bits 0–5 used | cradle `crates/cradle-common/src/lib.rs:754-806` |
| cradle per-role message pattern: `SetEsRole` → `es_render` owns its `ES_DF` rows | cradle `crates/cradle/src/control.rs:936,1056` |

**Name collisions to avoid.** "Leaf" already means three other things in
the BGP code: AR-LEAF (`AssistedReplicationRole::Leaf`, `inst.rs:736`), the
RFC 9572 Leaf A-D route (`evpn_originate_leaf_ad`, `route.rs:23391`), and the
PMSI L flag. Everything new here is spelled **`etree`**: `EtreeEc`,
`etree_leaf_label`, YANG `etree`, counters `l2_drop_etree_*`.

## 4. Wire format

### 4.1 The E-Tree extended community

RFC 8317 §6.1, with the Root-Indication flag from rfc8317bis §7.1:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=0x06     | Sub-Type=0x05 |   MBZ     |R|L|  Reserved=0   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Reserved=0   |          Leaf Label (or Leaf VNI)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

L is bit 7 (the low-order bit) of the flags octet, R is bit 6. An MPLS
leaf label occupies the **high-order 20 bits** of the 24-bit field. The
community is transitive.

What the community means depends on the route carrying it:

| Carried on | Flags | Field | Receiver rule |
| ---------- | ----- | ----- | ------------- |
| **Type-2** (MAC/IP) | L **MUST** be 1 | label SHOULD be 0, **MUST be ignored** | L=0 is invalid: log an error (we then treat the MAC as root) |
| **Type-1 EAD-ES with ESI 0** | L SHOULD be 0, **MUST be ignored** | a valid, non-reserved MPLS label | an invalid label is ignored and logged |
| **Type-3 IMET** (VXLAN only, not RFC 8317) | rfc8317bis: L, R per §5.6 table; Arista draft: L=1 | rfc8317bis: leaf VNI; Arista: 0 | see §8.5 |

The absence of the community means **root** (RFC 8317 §4.1). That is the
backward-compatibility rule everything below leans on: a PE that knows
nothing of E-Tree is a root-only PE, and is correct as one.

### 4.2 The leaf-label route (EAD-ES, ESI 0)

RFC 8317 §4.2.1: one leaf label **per PE** (not per ESI, not per EVI),
advertised on an Ethernet A-D per-ES route with **ESI = 0** and the RTs of
**every EVI on this PE that has at least one leaf AC**. If the RT set does
not fit one route, advertise several (RFC 8317 §4.2.1). Our per-ES A-D key is
`[1]:[ESI]:[MAX-ET]` under RD `<rid>:0`, so the leaf-label route is
`[1]:[0]:[MAX-ET]` under `<rid>:0`.

**Collision found while writing this:** `esi_from_str`
(`crates/bgp-packet/src/attrs/nlri_evpn.rs:724`) accepts the all-zero ESI,
so an `ethernet-segment` configured with ESI 0 would originate the same
NLRI. RFC 7432 §5 reserves ESI 0 for single-homed sites, and MAX-ESI too.
Phase 1 refuses both at commit (`check_es_esi`, run by `config::check`).
A startup config is only warned about, as for the MPLS label checks,
because an earlier release accepted any ESI. The setter then leaves that
segment without an ESI.

### 4.3 The composite PMSI tunnel bit

RFC 8317 §6.2 sets the high bit of the PMSI tunnel type when a Root PE
transmits on a P2MP tree but receives by ingress replication, and puts a
3-octet label in front of the tunnel identifier. We never originate it (no
P2MP on an E-Tree BD). On receive, our `PmsiTunnel::parse_be`
(`pmsi_tunnel.rs:235`) expects a bare 4- or 16-octet endpoint, so a
composite identifier **fails to parse**. RFC 8317 says a PE that does not
understand the bit treats the attribute as malformed per RFC 6514 —
treat-as-withdraw, **not** a session reset.

Ours reset the session: `PmsiTunnel` was not in
`attr_malformation_is_withdraw` (`attrs/attr.rs`). Phase 1 adds it, so a
PMSI Tunnel attribute that does not parse withdraws the UPDATE's routes.
That covers more than the composite bit: any tunnel identifier other than
an IPv4 or IPv6 address, or an SR P2MP tree, fails to parse. Examples are
RSVP-TE P2MP, mLDP and PIM trees. Phase 1 also refuses the composite range
(0x80–0xFA, RFC 8317 §8.1) in `PmsiTunnel::parse_be` outright. Otherwise a
13-octet transmit identifier behind the 3-octet label would be read as an
IPv6 endpoint.

## 5. Roles and configuration

### 5.1 What an AC is here

zebra-rs has no E-LAN AC object. An AC is a **kernel netdev enslaved to a
bridge** (`set interface X bridge BR`); its EVIs come from
`Bgp::port_evis`. In cradle the same netdev becomes an L2 `Port` with
exactly **one** bridge domain. A VLAN sub-interface is just another netdev,
so "role per AC" in RFC 8317's sense (an AC identified by the Ethernet tag,
§4.2) is "role per netdev" here. No new AC object is needed.

### 5.2 Configuration surface (decision D1: adopted)

```
router bgp <asn>
 afi-safi evpn
  etree
   leaf-interface ce2          # list, key = interface name
   leaf-interface bond0        # a multihomed leaf: name the ES's interface
```

- Any AC **not** listed is a root. RFC 8317 §7: default-root is the
  backward-compatible choice, so the operator SHOULD configure the role
  before activating the AC. §7.3 invariant 6 makes the datapath fail closed
  while the role is in flight.
- A root-only PE needs **no configuration at all**. Ingress filtering only
  ever drops traffic from a leaf AC, and egress filtering only protects
  leaf ACs.
- This sits beside `ethernet-segment … interface`, which already names ACs
  by interface under the same subtree.
- Adding BGP config paths trips `bgp_config_audit_tests`. Regenerate with
  `ZEBRA_UPDATE_AUDIT_DOCS=1 cargo test -p zebra-rs bgp_config_audit`, and
  bump the `docs/orphan-report.txt` Total/Handled counts by hand.
- Until BUM filtering exists for the configured encapsulation, the subtree
  stays behind a YANG `feature`/`if-feature` gate (decision D5, adopted:
  `--feature etree`, `zebra-features.yang`). A half-built E-Tree that floods
  leaf BUM to leaves must not look finished.

### 5.3 Multihomed leaves

RFC 8317 §4.2.3 **assumes** a VLAN has the same role on every PE of the ES.
Nothing on the wire states an AC's role, so the assumption cannot be
enforced, only checked. The violation is also not benign: a leaf-originated
BUM copy carries the leaf label **instead of** the ESI label (§8.4), so if
the peer PE's AC on that ES is a root, the copy goes back out of the segment
it came from — a loop.

What we can see is the same MAC advertised with the ESI of a segment we also
attach to, with a leaf flag that disagrees with our own AC's role. `show`
reports that as an `etree role conflict on <esi>`, and it is logged once per
onset/clear.

## 6. Who drops what, where

| Traffic | Filter | Where | Encapsulations |
| ------- | ------ | ----- | -------------- |
| local leaf AC → local leaf AC, unicast and BUM | intra-PE split-horizon group (RFC 8317 §4.2) | cradle, ingress PE | all |
| local leaf AC → **known** remote MAC flagged leaf | **ingress** filtering (§4.1) | cradle `l2_evpn_xdp`, before encapsulation | all — only needs the Type-2 colouring |
| local leaf AC → BUM toward remote PEs | tag the copy as leaf-originated | cradle replication slots | MPLS: the remote PE's leaf label (§8.4). VXLAN: decision D2 (§8.5). SRv6: Arg.FE2 (§8.6) |
| remote leaf-originated BUM → local AC | **egress** filtering: deliver to roots only | cradle `flood` on decap | per the tag above |
| anything from a root AC | none — RFC 7432 unchanged | — | all |

Known unicast is filtered at the **ingress** PE, so it never crosses the
core (RFC 8317 §4.1). BUM cannot be filtered there, because one copy serves
roots and leaves alike, so it is filtered at the **egress** PE (§4.2).

## 7. Control plane

### 7.1 Origination

1. **Type-2 colouring.** `evpn_originate_macip` already resolves the ESI from
   `FdbEntry.ifindex` (`macip_esi`). Resolve the role in the same place: a
   MAC learned on a leaf AC carries `EtreeEc { leaf: true, label: 0 }`.
   Adding or removing a `leaf-interface` runs the existing
   `evpn_resync_macip_esi` over the cached local FDB. A role change is an
   attribute change, an implicit replace; no MAC-mobility sequence bump.
2. **The leaf label.** Add a `Bgp::etree_leaf_label: Option<u32>` that
   mirrors `EthernetSegment.esi_label`:
   - `etree_label_reconcile()` allocates it from `service_labels` when the
     encapsulation is MPLS and at least one EVI has a leaf AC, and frees it
     otherwise;
   - hook it into `service_labels_reconcile` for the range-full recovery
     path, exactly as `es_label_reconcile` is;
   - like the ESI label, it installs **no ILM**. cradle resolves it in its
     own map (§8.4).
3. **The leaf-label route.** `evpn_originate_etree_leaf_ad()` is a per-ES A-D
   with ESI 0, through `evpn_originate_synch`. It carries:
   - the E-Tree EC with the label;
   - the RT of every EVI with a leaf AC (split into several routes when the
     set is too large).

   It is re-originated whenever that RT set or the label changes, and
   withdrawn when the last leaf AC goes.
4. **IMET colouring (VXLAN only, phase 4).** See §8.5.

### 7.2 Consumption

1. **Type-2.** The leaf flag is read from the **selected** path only.
   RFC 8317 §4.1: MAC-mobility procedures "take precedence to first identify
   the location of the MAC before associating that MAC with a Root or a
   Leaf site", so the flag follows best-path selection, which already
   applies mobility.

   `extract_flags_from_attr` gains a bit (`MacRoute.flags`, next to sticky,
   gateway and router); `mac_install` hands it to cradle. A received
   E-Tree EC with L=0 on a Type-2 is logged and treated as root.
2. **Leaf-label routes.** Add a new consumer: per remote PE, the leaf label
   from its ESI-0 per-ES A-D, gathered the way `es_peer_esi_labels` gathers
   ESI labels and fed to the replication tee alongside them (§8.4). Today
   such a route is stored and ignored (§3). After this change it is consumed
   **only** when it carries an E-Tree EC with a valid label.
3. **IMET (VXLAN).** See §8.5.

### 7.3 Invariants

1. **No community means root.** A route we cannot classify never causes a
   drop.
2. **Root-sourced traffic is never filtered** by any E-Tree rule.
3. **The leaf flag follows the selected Type-2 path.** A MAC that moves from
   a leaf AC to a root AC stops being dropped when the move is selected, not
   when some copy of the route arrives.
4. **A leaf label is used only toward the PE that advertised it.** Labels are
   downstream-assigned for ingress replication (RFC 8317 §4.2). A remote PE
   that advertised none has no leaf ACs, so it gets an untagged copy.
5. **The leaf label replaces the ESI label, never stacks with it** (RFC 8317
   §4.2.3).
   This is also what cradle's single extra label slot can carry (§3).
6. **Fail closed while the role is in flight.** cradle accepts a port role
   before the port itself exists (as `SetEsRole` does today), and the RIB
   sends the role before or with the port binding. A leaf AC must never
   switch to another leaf AC for even one window because its role arrived
   second.

## 8. Datapath (cradle)

### 8.1 Why cradle-only

The kernel bridge cannot do any of the following:
- drop by **destination MAC colour**: no FDB attribute means "this MAC is a
  leaf";
- push or read a **leaf label**: the kernel EVPN path is VXLAN-only and
  single-homed by decision;
- tell a leaf-originated VXLAN frame from a root one.

What it *can* do is local isolation: bridge-port `isolated on` stops
isolated ports talking to each other, which is exactly a local leaf group.
`vxlan_bridge_port_defaults` (`fib/netlink/handle.rs:3234`) already holds
the `InfoBridgePort` setter that would set it.

Local isolation alone is the least valuable third of E-Tree, though, and
shipping it would let an operator believe leaves are isolated across the
core when they are not. Decision D3 (adopted): a leaf AC is refused at
commit unless the cradle data plane is on (`system ebpf enabled` or
`system cradle enabled`; `config::check::etree_backend`). A startup config
is only warned about, as for the MPLS label checks: refusing the file
would leave the router unconfigured.

### 8.2 Port role and local filtering

- **New RPC.** `SetPortRole{port, leaf}`, stored by port name, applied when
  the port appears. As built (cradle-rs #204): `SetEtreeRole{port, leaf}`.
- **New map.** `PORT_ETREE: ifindex → flags`, with its own owner. Do **not**
  fold the role into `PortConfig.flags` or `ES_DF`: `SetPort` and
  `es_render` rewrite those wholesale, so a role kept there would be wiped
  on the next re-render. `ES_DF` also only covers segment ports.
- **Local unicast.** In the TC redirect path (`main.rs:882-901`), drop when
  both the ingress port and the FDB's `oif` are leaves.
- **Local BUM.** In `flood`, skip leaf members when the ingress port is a
  leaf.
- Counter `l2_drop_etree_local`.

### 8.3 Known unicast across the core

- **Proto.** `FdbRemote` gains a `flags` field. It has none today (proto
  `:233`). As built (cradle-rs #204): a bool, `FdbRemote.etree_leaf = 9`.
- **FDB.** Add `FDB_F_ETREE_LEAF = 1 << 6` in `FdbEntry.flags`.
- **Check.** In `l2_evpn_xdp`, between the FDB lookup and the single encap
  call (`main.rs:3383-3437`): if the ingress port is a leaf and the entry is
  flagged, drop. Counter `l2_drop_etree_uc`.
- The check is identical for VXLAN, MPLS and SRv6, and also covers
  `FDB_F_ESNHG` entries, because the flag lives on the MAC, not on the
  path.
- `l2_overlay_encap` stays the single encap call site in `cradle_xdp`. The
  verifier stack budget requires it (`main.rs:3370-3375`).

### 8.4 MPLS BUM

**Transmit.** A leaf-originated copy to remote PE *X* carries *X*'s leaf
label under the EVI service label. That label is per remote PE, which in
cradle's model means per replication slot, just as an ESI-labelled copy
uses a per-ES slot today (`SLOT_ES`, `ReplTarget.esi_label`):
1. Add a **leaf slot** per (BD, remote PE that advertised a leaf label),
   whose `ReplTarget` carries that label in the existing extra-label field.
2. In `flood`, a frame from a leaf port uses the leaf slots, plus the plain
   slots of PEs with no leaf label. It never uses the ESI-labelled slots:
   per RFC 8317 §4.2.3, the leaf label alone also protects the leaf AC on
   the same segment.
3. Counter `mpls_l2_leaf_push`.

**Receive.** `pop_decap_l2` today drops any second label that is not an ESI
label:
1. Add our own leaf label to a `LEAF_LABEL` map, or to `ESI_LABEL` with a
   reserved id.
2. On a hit, set a leaf bit in `CradleXdpMeta`: a new flags word, or bit 63
   of `es_bits`, which costs one of the 64 ES ids. Either way it must stay
   within the XDP metadata size limit.
3. `tc_meta_l2` → `l2_switch` → `flood` then skips leaf ports.
4. Counters `mpls_l2_leaf_pop` and `l2_drop_etree_bum`.

### 8.5 VXLAN BUM (decision D2)

VXLAN has no label to carry the leaf mark, and there is no standard. The
options are:

**V1+ — IMET colouring with flood-list pruning plus source-VTEP egress
filtering.** This is the Arista draft's wire format, with one zebra-rs
addition.
- A PE whose ACs in a BD are **all** leaves puts `EtreeEc{L=1, label 0}` on
  that BD's IMET. A PE with any root AC in the BD does not.
- **Ingress (draft).** A PE sending leaf-originated BUM leaves the leaf-only
  PEs out. Its leaf ports use a "non-leaf" flood list: rfc8317bis §5.6.3
  condition 4, applied with the draft's wire signal.
- **Egress (addition).** A receiving PE marks a leaf-only PE's VTEP as
  leaf-sourced for that BD, and `flood` keeps BUM from it off local leaf
  ports. cradle already looks up the outer source on decap for local bias
  (`vtep4_es_bits`, `main.rs:921`), so this is one more bit per peer.
- **Exactness.** V1+ is exact unless **two PEs in the same BD each have both
  root and leaf ACs**. Leaf-originated BUM between two such *mixed* PEs is
  indistinguishable from root BUM, and reaches the other's leaves.
- **Cost.**
  - zebra: an IMET EC, plus a filter in `EvpnFloodState::reconcile`.
  - cradle: a per-(BD, VTEP) leaf bit, plus leaf-port flood-list selection.
  - The kernel backend could even do the pruning half.
- **Interop.** Arista cEOS speaks it.

**V2 — rfc8317bis leaf VNI.**
- A second, domain-wide **leaf VNI** per BD, carried in the IMET's E-Tree EC
  with the R/L flags.
- Leaf-originated BUM is encapsulated with the leaf VNI, and the egress PE
  delivers leaf-VNI frames to root ACs only.
- **Exactness.** Exact for every mix of roles.
- **Cost.**
  - Leaf-VNI configuration on every PE.
  - cradle: `VNI_INFO` grows a leaf entry per BD, and transmit chooses the
    VNI by ingress role.
- **Interop.** Wire-incompatible with V1: a V2 receiver discards a label-0
  IMET (§2). No implementation found, and the draft is expired.

**Recommendation: V1+**, with `show` naming a BD that has two or more mixed
PEs as `etree: leaf BUM not isolated between mixed PEs`. Revisit V2 if
rfc8317bis is revived and someone ships it.

### 8.6 SRv6 BUM (decision D6: adopted)

The leaf mark over SRv6 is an **Arg.FE2** argument of the egress PE's
End.DT2M SID (RFC 8986 §4.12). The argument is opaque, and its value is
local to the egress PE: the egress PE allocates it and signals it in the
control plane, and only the egress PE interprets it.

**Standards.** RFC 9819 (formerly draft-ietf-bess-bgp-srv6-args, July
2025, updates RFC 9252) is what to follow:
- it replaces RFC 9252 §6.3's bitwise OR, which assumed a uniform SID
  structure, with explicit placement: the argument goes at offset
  LBL+LNL+FL of the IMET's End.DT2M SID (§3.3);
- the IMET carries the End.DT2M SID (LOC:FUNC) with an AL, and the
  argument rides an Ethernet A-D per-ES route with the same AL (§3.2: AL
  MUST be equal; §3.1: AL SHOULD be a multiple of 8);
- an IMET with AL 0 means "no argument": the ingress PE sends to LOC:FUNC
  and ignores any argument (§3.3).

rfc8317bis §5.4 applies it to E-Tree: the leaf argument is allocated per
PE (not per ES, not per EVI) and signalled in the same ESI-0 per-ES A-D
route as the MPLS leaf label (§4.2), with the RT of every BD that has a
leaf AC. The ingress PE applies it only to BUM from a leaf AC. The draft
expired in April 2026, but its SRv6 section is RFC 9819's procedure with
ESI 0.

**Implementations** (EANTC 2026 interop report, Nokia documentation): every
participant used LBL 32, LNL 16, FL 16, **AL 16**. Cisco, Nokia and Ciena
transpose the argument into the ESI Label EC (TL 16, TO 64); HPE (Juniper)
and Raisecom carry it in the SID itself. No vendor documents E-Tree over
SRv6, and FRR has no Arg.FE2 at all.

**Decisions** (each the recommendation, adopted 2026-10-15):
1. **AL 16, right after the function.** zebra-rs already places its 16-bit
   function immediately after the locator (`function_addr`), so the
   argument is the next 16 bits: for a uSID /48 locator that is exactly
   LBL 32, LNL 16, FL 16, AL 16. A locator too long to fit 16 more bits
   gets no leaf argument (and `show` says so).
2. **No transposition.** The argument rides in the SID of the A-D route's
   SRv6 L2 Service TLV (TL 0), as RFC 9819's examples do. A received
   leaf route that transposes (TL > 0) is logged and not used: no vendor
   documents E-Tree over SRv6, so there is no peer to match yet, and
   where the bits would go on an ESI-0 route (it has no ESI Label EC) is
   not specified anywhere.
3. **One leaf argument per PE, value 1.** Values are local; 0 means none.
   If RFC-style ESI filtering over SRv6 is ever added (today's split
   horizon is local bias by outer source), its per-ES values come from the
   same 16-bit space and must avoid the leaf value.
4. **AL 16 on the IMET only where it is needed.** A PE advertises AL 16 on
   a VNI's End.DT2M SID only while it has a leaf AC in that VNI (it is the
   only one that allocated an argument). Every other deployment's routes
   stay byte for byte the same.
5. **The E-Tree EC rides the SRv6 leaf route too**, with field 0. rfc8317bis
   §7.1 requires a valid MPLS label in it, but that text predates SRv6;
   the EC is what marks an ESI-0 A-D route as a leaf-indication route, and
   zebra-rs's receivers already ignore a reserved label.

**Datapath (cradle, phase 5a).**
- *Decap.* A local End.DT2M SID with an argument is installed as its
  LOC:FUNC prefix (LBL+LNL+FL bits), so the LPM lookup matches any
  argument. `srv6_dt2u` reads the AL bits at that offset: this PE's leaf
  argument sets `ES_BITS_ETREE_LEAF`, and phase 3a's egress filter keeps
  the copy off leaf ports. Any other non-zero value is unknown and
  dropped; 0 is plain BUM. `LocalSid` gains the argument offset and length
  (the proto's `arg_bits` is today dropped by the handler); a new
  `SetEtreeLeafArg` sets the leaf value (0 = none).
- *Encap.* A leaf slot toward a PE is a replication slot whose SID is that
  PE's End.DT2M SID with its leaf argument already placed (zebra-rs
  computes it). It reuses phase 3a's `SlotEs.etree` selection: a leaf's
  BUM goes through the PE's leaf slot alone, and its other slot serves
  roots only.

**Control plane (zebra-rs, phase 5b).**
- Allocate nothing new: the leaf argument is the constant 1, and AL 16 is
  advertised per decision 4.
- Originate the ESI-0 A-D route under SRv6 as under MPLS (§4.2), with the
  SRv6 L2 Service TLV carrying `::<arg>` at offset LBL+LNL+FL and the SID
  Structure Sub-Sub-TLV (LBL, LNL, FL, AL 16, TL 0).
- Read each peer's argument from its ESI-0 A-D route, check its AL against
  that peer's IMET AL (RFC 9819 §3.3: unequal non-zero ALs mean no leaf
  BUM to that PE), and tee a leaf slot `(bd, PE, DT2M SID | arg)`.
- Install the local End.DT2M SID with its argument shape, and tee the leaf
  argument to cradle.

### 8.7 Counters

These append to `STAT_NAMES` (cradle `control.rs:73`), which is positional
and tied to `STAT_MAX`:
- `l2_drop_etree_local`
- `l2_drop_etree_uc`
- `l2_drop_etree_bum`
- `mpls_l2_leaf_push`
- `mpls_l2_leaf_pop`

Each drop counter needs a BDD that asserts it non-zero in the treatment
**and** zero in a control (§10).

## 9. Show / observability

- **Route display.** `show bgp evpn route` renders the community through
  `ExtCommunityValue`'s `Display`. The EC alone does not say which route
  carries it, so `EtreeEc`'s `Display` picks by its bytes:
  - `etree:leaf`: L only, no field. This is a Type-2, or an IMET in the
    Arista form (V1+), which has the same bytes;
  - `etree:leaf-label:<n>`: no flags, a field (ESI-0 A-D);
  - otherwise `etree:` then `R`/`L` (`-` for neither), then `:vni:<n>` if
    there is a field. This is the rfc8317bis IMET form, and how an invalid
    combination shows: a Type-2 with L clear is `etree:-`.
- **`show bgp evpn etree`** (and JSON) shows:
  - the local leaf ACs per EVI, with whether each one's role is programmed;
  - our leaf label, and the RT set on the leaf-label route;
  - per remote PE: its leaf label (MPLS) or IMET role (VXLAN);
  - per EVI, the number of remote MACs flagged leaf;
  - warnings:
    - `role conflict on <esi>` (§5.3);
    - `kernel backend: not enforced` (D3);
    - `IRB on an E-Tree BD: leaves can reach each other through L3`
      (§1.1);
    - `leaf BUM not isolated between mixed PEs` (§8.5).
- **Logging** (info, `category = "evpn"`): leaf-label allocation and release,
  each role conflict onset and clear, and every invalid E-Tree EC received
  (L=0 on a Type-2, a bad label on an ESI-0 A-D).

## 10. Phasing

Smallest first. Each phase is independently mergeable, and a cradle half
lands, is released and is pinned (`cradle-version`, the #2482 precedent)
before the zebra half that drives it.

| Phase | Deliverable | Repo | Gate |
| ----- | ----------- | ---- | ---- |
| **1** ✅ | **Codec + guards**: `EtreeEc` (L, R, label/VNI) parse/emit/`Display`/`is_`/`as_`; unknown flag bits preserved; reject ESI 0 on `ethernet-segment` at commit; confirm (and if needed fix) composite-PMSI receive = treat-as-withdraw | zebra | unit round-trips incl. the RFC 8317 figure; mutation of the L-bit position must fail a test |
| **2a** | **cradle roles + known unicast**: `SetPortRole`, `PORT_ETREE`, local leaf↔leaf drop, `FdbRemote.flags`, `FDB_F_ETREE_LEAF`, XDP ingress check, counters | cradle | static-config BDD: leaf→leaf (local and remote) dropped with the counter non-zero; **control** = the same topology with one AC a root, ping passes and counter zero |
| **2b** | **zebra roles + Type-2 colouring**: `etree leaf-interface` (behind the feature gate), role tee via a new RIB message, Type-2 EC origination + resync, selected-path flag → `MacRoute` → `FdbRemote.flags`, `show bgp evpn etree` | zebra | zebra BDD: Type-2 shows `etree:leaf` only for leaf-AC MACs; cradle zebra-driven VXLAN BDD: remote leaf→leaf unicast dropped, leaf→root passes; MAC move leaf→root un-drops |
| **3** | **MPLS BUM**: leaf label lifecycle, ESI-0 leaf-label A-D origination + consumption, cradle leaf slots, `LEAF_LABEL` decap, egress flood filter | both | cradle MPLS zebra-driven BDD: leaf broadcast reaches roots only; multihomed leaf: the copy carries the leaf label and **not** the ESI label (`mpls_l2_esi_push` stays zero); control = root broadcast reaches leaves |
| **4** | **VXLAN BUM** per D2 (V1+ recommended): IMET colouring, flood-list pruning, source-VTEP egress bit | both | BDD with a leaf-only PE and a mixed PE; `show` warning for two mixed PEs |
| **5** | **SRv6 BUM** per D6 (§8.6): 5a cradle — an argument-aware End.DT2M (the leaf argument marks the copy), `SetEtreeLeafArg`, SRv6 leaf slots; 5b zebra — the leaf argument on the ESI-0 A-D, AL 16 on the IMET, leaf slots from peers' arguments | both | BDD as phase 3 over SRv6 |
| **6** | **Docs + interop**: book chapter, `bgp-evpn-support-status.md` row, lab against Arista cEOS (VXLAN: Type-2 + IMET) and a Nokia/Juniper image (MPLS) | — | the lab report |

**Status: phase 1 is implemented** on `evpn-e-tree`.
- **Codec.** `ExtCommunityValue::etree_leaf()` (Type-2) and
  `etree_leaf_label(n)` (ESI-0 A-D) build the EC; `is_etree` / `as_etree`
  decode it into `EtreeEc { flags, field }`. `flags` keeps the MBZ bits as
  received. `valid_leaf_label()` drops the reserved labels 0–15.
- **Tests.** The tests pin Appendix A's bytes. Mutants that move L or R,
  drop the 4-bit label shift, or accept a reserved label each fail a test.
- **ESI guard.** ESI 0 and MAX-ESI are refused at commit and warned about
  at startup (§4.2).
- **PMSI.** A malformed PMSI Tunnel attribute, a composite one included, is
  treat-as-withdraw (§4.3). Not done: RFC 6514 §5 requires an error log
  when a malformed PMSI is detected. Nothing is logged for it, nor for any
  other treat-as-withdraw attribute, because the parser reports only a
  bool. That is a follow-up across all of them.

**Phase 2a is merged** as cradle-rs #204, released in cradle-rs v1.1.4,
which zebra-rs pins since #2522. Two names differ from §8.2-§8.3: the RPC is
`SetEtreeRole`, and the remote MAC's flag is `FdbRemote.etree_leaf`, a bool.
`DelPort` leaves a port's role row, as it leaves the multihoming rows: the
port stays in its flood list until the caller's `SetL2Domain` (a review
finding).

**Status: phase 2b is implemented** on `evpn-e-tree`.
- **Config.** `router bgp afi-safi evpn etree leaf-interface <if>` (D1)
  exists only with `--feature etree` (D5). A commit naming a leaf AC
  without the cradle data plane is refused (D3, `config::check`).
- **Roles go through the cradle supervisor, not a RIB message.** The
  supervisor (`cradle/inst.rs`) already receives `router bgp` config (the
  EVI bridge) and owns `SetPort`. So it sends every `SetEtreeRole` before
  any port moves (`sync_etree_roles`), and a leaf whose role the engine has
  not acknowledged is held out of the datapath: not attached, or detached
  (`etree_held`). A respawned engine gets every role back before its
  ports. That is invariant 6 (§7.3) by construction; a RIB-side tee would
  race the supervisor re-attaching the ports of a fresh engine. Ports
  zebra-rs does not attach (an external engine's own port config) are the
  exception: their role arrives when zebra-rs sends it.
- **Type-2 origination.** `evpn_originate_macip` adds the E-Tree EC (L=1)
  to a MAC learned on a leaf AC (`macip_etree_leaf`). A role change
  re-originates the cached local MACs, with no sequence bump
  (`config_etree_leaf_interface`). So does a leaf AC's link becoming known
  to BGP after MACs were learned on it (cradle's learn replay can beat the
  link dump), which would otherwise leave them advertised as roots.
- **Type-2 receive.** `extract_flags_from_attr` sets `MAC_FLAG_ETREE_LEAF`
  from the selected path. A Type-2 carrying the EC with L clear is logged
  and treated as a root (`etree_leaf_flag_missing`). The flag rides
  `MacRoute.flags` and `MacEntry.flags` to `mac_add`, which hands it to
  cradle as `FdbRemote.etree_leaf` for VXLAN, MPLS, SRv6 and
  segment-group entries. It is mirrored, so an engine replay keeps it.
- **Show.** `show bgp evpn etree` lists the leaf ACs, their EVIs and local
  MACs, and the remote leaf MACs per EVI. `show bgp evpn` renders the EC
  (`etree:leaf`), which had fallen back to hex. `show l2 mac table` flags a
  leaf MAC `L`. `show ebpf` lists the leaf roles and whether each is
  programmed, and `show ebpf l2` shows `etree-leaf`.
- **Local MACs come from cradle's learning.** While cradle's `WatchFdb`
  runs, the kernel bridge's learns are not advertised
  (`FibMessage::NewNeighbor`). So the BDD uses real hosts on engine ports,
  not static bridge entries.
- **Tests.**
  - Unit tests cover the commit check (feature gate and cradle
    requirement), Type-2 colouring (including a role change keeping the
    sequence number, and a late link), the receive flag, the invalid-EC
    case, the supervisor's hold, and the `show bgp evpn` rendering.
  - BDD `bgp_evpn_etree` (zebra-rs, managed cradle) covers the refused
    commit, the programmed roles, local leaf isolation with
    `l2_drop_etree_local` non-zero, the flag in the remote engine's FDB,
    an engine restart, and a leaf turned into a root.
  - Mutants: removing the colouring, the receive flag, the tee's flag, the
    commit check, the role sync, the reset of acknowledged roles on an
    engine restart, the re-origination on a role change, or the root on
    removal each fail it.
  - Two test traps turned up and are guarded in the feature: an idle host's
    IPv6 router solicitations make cradle re-report its MAC, and the
    engine restart's learn replay lands seconds later. Either one
    re-advertises a MAC by itself and hid a missing re-origination.
  - cradle-rs BDD `cradle_evpn_etree_zebra` covers the cross-core
    known-unicast drop driven by zebra-rs, with each PE's
    `l2_drop_etree_uc` counted, and a host moving from a leaf AC to a root
    AC becoming reachable from the leaves.
- **Not in 2b:** the multihomed role-conflict warning (§5.3) and the IRB
  warning (§9, D4).

**Phase 3a is merged** as cradle-rs #207, released in cradle-rs v1.1.5,
which zebra-rs pins since #2524. It is §8.4 as planned, with these
choices:
- **Leaf mark.** The decap leaf mark is bit 63 of `es_bits`
  (`ES_BITS_ETREE_LEAF`), so segment ids stop at 62.
- **Leaf label on the wire.** The leaf label rides `ReplTarget.esi_label`,
  marked above the 20 label bits. The encap path keeps its signature, for
  the verifier budget.
- **Slot selection.** `SlotEs.etree` makes a leaf's flood use the PE's leaf
  slot alone, and makes the PE's other slots serve roots only.
- **A path the plan missed.** Egress filtering also covers `l2_switch`: a
  remote leaf's unknown unicast is flooded with the leaf label, and at the
  egress PE it can meet a MAC known there, which would otherwise be
  switched straight to a leaf.

**Status: phase 3b is implemented** on `evpn-e-tree`.
- **Leaf label.** `etree_label_reconcile` draws one per PE from the service
  labels while the encapsulation is MPLS and an EVI has a leaf AC, and
  hands it back otherwise. A leaf AC's EVIs are its `port_evis`, so under
  MPLS the AC must be in the EVI's bridge. The label is teed to cradle for
  decap (`EtreeLeafLabel`, mirrored) and installs no ILM.
- **Leaf-label route.** `evpn_originate_etree_leaf_ad` originates the
  per-ES A-D with ESI 0 under `<router-id>:0`, carrying the E-Tree EC and
  the RT of every EVI with a leaf AC. It is idempotent, and withdraws the
  old-RD route after a router-id change. The RTs ride one route (an
  extended-length attribute holds thousands).
- **Leaf slots.** `etree_peer_leaf_labels` reads each remote PE's label
  from its selected leaf-label route; a reserved label is ignored and
  logged on receipt. `evpn_etree_slots_sync` builds, per EVI with a local
  leaf AC, a slot toward every PE with a leaf label and a BUM label
  (`CradleReplAddMplsLeaf`). It runs off a new `LocalRib::etree_dirty`,
  which the leaf-label route and the MPLS IMETs set.
- **A tee that comes up later.** A leaf label drawn at config load precedes
  the cradle tee and never reached it. Every peer's leaf-labelled copy was
  then dropped as malformed. `RibRx::CradleUp` now re-sends the label and
  the slots, as it does the Ethernet Segment state. The zebra-driven BDD
  found this on its first run.
- **Show.** `show bgp evpn etree` shows this PE's leaf label and each
  remote PE's.
- **Tests.**
  - Unit tests: the label's lifecycle and route under MPLS, none under
    VXLAN, a peer's label making a leaf slot (its route withdrawn, the slot
    gone; a reserved label, none), and a new tee getting the label again.
  - cradle-rs BDD `cradle_evpn_etree_mpls_zebra` runs IS-IS SR-MPLS across
    a P router:
    - the labels cross in BGP;
    - a leaf's broadcast reaches the remote root but not the remote leaf
      (`l2_drop_etree_bum`), and a root's reaches both;
    - a leaf's known unicast to the remote leaf is dropped at its own PE.

    It fails without the leaf-label route, without the slot adds, or
    without the `etree_dirty` drain. Its first run is what caught the lost
    leaf label.

**Phase 4a is merged** as cradle-rs #210, released in cradle-rs v1.1.6,
which zebra-rs pins since #2527. It is §8.5's V1+ as planned:
- **`SetEtreeRemote{bd, remote, leaf_only}`** marks a remote VTEP leaf-only
  in one bridge domain (`VTEP_ETREE`, keyed per domain: a PE can be
  leaf-only in one and mixed in another).
- **Egress.** VXLAN decap ORs the leaf mark into the source lookup it
  already does for local bias, and the phase-3a filter keeps the copy off
  leaf ports.
- **Ingress.** The slot toward a leaf-only PE serves roots only, reusing
  phase 3a's `SLOT_ETREE_ROOT`.

**Status: phase 4b is implemented** on `evpn-e-tree`.
- **What an AC is.** zebra-rs learns a VNI's ACs from the kernel bridge:
  every port of the VNI's bridge (`port_evis`) that is not a VXLAN device
  (`Bgp::vxlan_links`, from `Link.vni` on `RibRx::LinkAdd`, because
  `VxlanAdd` carries no ifindex). That is how the cradle supervisor binds
  an L2 port too. A port that an external engine puts in the domain
  without bridging it is invisible, and a hidden root would make the VNI
  look leaf-only, so its leaves' BUM from other PEs would never reach it.
  Bridge every AC.
- **IMET colouring.** `etree_leaf_only_vnis` is the VNIs with a leaf AC and
  no root AC, under VXLAN only. `evpn_originate_imet` adds
  `EtreeEc{L=1, field 0}` for those VNIs. `etree_imet_reconcile`
  re-originates a VNI's IMET when its colour flips, and runs on any AC's
  bridge change (`L2PortEvis`), a link becoming or ceasing to be a VXLAN
  device, a link deleted, and every `etree_label_reconcile` (a role
  change, an EVI, the encapsulation).
- **Consumption.** `etree_leaf_only_remotes` reads the selected VXLAN IMETs
  (no MPLS BUM label, no End.DT2M SID) that carry the V1+ form: L set, R
  clear, field 0. The rfc8317bis form, a leaf VNI, reads as a root.
  `evpn_etree_remotes_sync` tees each `(VNI, VTEP)` as `CradleEtreeRemote`
  (mirrored as `SetEtreeRemote`) while this PE has a leaf AC, and is
  diffed against what was sent. It runs from the `etree_dirty` drain,
  which every IMET announce and withdraw now sets, and is re-sent to a new
  tee (`RibRx::CradleUp`).
- **Show.** `show bgp evpn etree` under VXLAN lists the leaf-only EVIs, the
  leaf-only remote PEs per EVI, and the warning
  `EVI <n>: leaf BUM not isolated between mixed PEs: <list>` when two or
  more PEs in an EVI are mixed (`etree_mixed_pes`): this PE when it has
  both kinds of AC there, a remote PE when it advertised a leaf MAC there
  without a leaf-only IMET. A remote leaf AC with no MAC learned yet is
  not seen.
- **Tests.**
  - Unit tests: the IMET colour following a root AC joining, leaving and
    being deleted (the VXLAN device is no AC), none under MPLS; a
    leaf-only IMET marking its PE and the mark cleared when the colour or
    the route goes, the rfc8317bis form ignored, nothing without a local
    leaf, a new tee getting the marks again; two mixed PEs reported, and
    the `show` text and JSON. Eleven mutants each fail one.
  - cradle-rs BDD `cradle_evpn_etree_vxlan_zebra`: a leaf-only pe1 against
    a mixed pe2. pe1's leaf broadcast is kept off pe2's leaf, pe2's leaf
    broadcast is not sent to pe1, and a root's still reaches pe1. A root
    AC added on pe1 makes it mixed: pe2 warns and the leaf broadcasts
    cross both ways (the control). The root AC leaving restores the
    isolation.
- **A test gap found on the way.** cradle-rs had no
  `command … should contain` step, and cucumber skips an unmatched step
  without failing. The tc-counter "nothing received" checks in
  `cradle_evpn_etree_mpls`, `cradle_evpn_etree_mpls_zebra` and
  `cradle_evpn_etree_vxlan` never ran. The step is added with this phase,
  and those features re-run with it.

**Review lessons carried over from the single-active arc** (see that plan
and the memory notes):
- Every negative assertion ("leaf did not receive") is first shown to fail
  with the filter removed.
- A test whose two rules agree proves nothing. For example, a leaf→leaf
  drop test where the destination is *also* unreachable for some other
  reason.
- Every behavioural sentence in the phase-6 docs names the function that
  implements it.

## 11. Risks and open decisions

**Decisions for the user** (D1, D3 and D5 decided 2026-10-14, D2 and D6
2026-10-15, each as recommended; D4 open):
- **D1 — Where the role is configured.** Decided:
  `router bgp afi-safi evpn etree leaf-interface <if>` (§5.2). Alternatives:
  - per EVI (`evi <id> etree leaf-interface …`), which only exists in the
    MPLS-shaped model today;
  - on the interface itself, next to `interface X bridge BR`.
- **D2 — VXLAN BUM.** Decided 2026-10-15: V1+ (§8.5). The alternatives
  were V2 and known-unicast-only for VXLAN.
- **D3 — A leaf AC under the kernel backend.** Decided: reject at commit
  (isolation is a security property, RFC 8317 §7). The alternative was to
  accept and warn.
- **D4 — IRB on an E-Tree BD.** Warn (recommended) or reject at commit.
- **D5 — Gating.** Decided: keep `etree` behind a YANG feature until BUM
  filtering exists for the configured encapsulation. The alternative was to
  ship each phase visible with `show` naming what is not yet filtered.
- **D6 — The SRv6 leaf argument.** Decided 2026-10-15 as recommended
  (§8.6): RFC 9819 placement, AL 16 right after the function, no
  transposition, one leaf argument per PE (value 1), AL 16 on a VNI's IMET
  only while it has a leaf AC, and the E-Tree EC (field 0) on the SRv6
  leaf route.

**Risks:**
1. **No FRR partner.** Every claim is zebra-rs against zebra-rs until the
   phase-6 lab runs against commercial images, and the book must say so.
2. **The VXLAN standard may move.** If rfc8317bis is revived with the leaf
   VNI, V1+ peers and V2 peers will not interoperate on BUM (§2). Keep the
   IMET colouring behind its own knob so it can be switched.
3. **Multihomed role mismatch is a loop, not a leak** (§5.3). Detection only
   — there is no signalling to enforce it.
4. **The ESI 0 collision** (§4.2) predates this plan: an ES configured with
   ESI 0 is already accepted today.
5. **Verifier budget.** The cradle XDP path is near its stack limit. The
   known-unicast check must stay out of a second encap call site.

## Appendix A — wire examples

```
Type-2, MAC learned on a leaf AC:
  06 05 01 00 00 00 00 00        E-Tree EC: L=1, label 0

ESI-0 per-ES A-D, leaf label 1000 (0x3E8 << 4 = 0x003E80):
  06 05 00 00 00 00 3E 80        E-Tree EC: L=0, label 1000

IMET, V1+ (Arista draft), leaf-only PE for the BD:
  06 05 01 00 00 00 00 00        E-Tree EC: L=1, label 0
```

## Appendix B — sources

- RFC 8317, *Ethernet-Tree (E-Tree) Support in EVPN and PBB-EVPN*, §3, §4,
  §6, §8.
- RFC 9252, *BGP Overlay Services Based on SRv6*, §6.1.1, §6.3.
- RFC 8365, *A Network Virtualization Overlay Solution Using EVPN* — no
  E-Tree procedure; §8.3.1 split horizon by local bias.
- draft-ietf-bess-rfc8317bis-00 (2025-10, expired 2026-04), §5.3, §5.4,
  §5.6, §7.1, §9.
- draft-bamberger-bess-imet-filter-evpn-etree-vxlan-00 (2023, expired), §3.
- Vendor documentation (unverified in a lab): Nokia SR OS *EVPN-MPLS
  E-Tree*; Juniper *EVPN-ETREE Overview*; Arista EOS *EVPN E-Tree for MPLS
  and VXLAN*; FRR *EVPN* (no RFC 8317).
