# EVPN Support Status by Encapsulation

Status as of 2026-08-02.

A framing fact that applies to all three encapsulations: the EVPN control
plane (route types 1–6 and 9–11, ESI multihoming with DF election, MAC
mobility) is shared and encapsulation-agnostic in zebra-rs. What differs per
encapsulation is the data plane — the Linux kernel natively forwards only
VXLAN, so all SRv6-L2 and MPLS-L2 forwarding runs in the cradle-rs eBPF
datapath, driven from zebra-rs via the FibHandle tee.

**Multihoming is cradle-only (decision 2026-08-28).** The EVPN-MH forwarding
behaviours — non-DF BUM filter, split-horizon/local-bias filter, ES nexthop
group (aliasing / mass withdraw), single-active enforcement — will be
implemented in the cradle-rs eBPF datapath for all three encapsulations and
driven from zebra-rs. The kernel VXLAN backend remains **single-homed**: the
Linux bridge has no dataplane for the two filters (see
`bgp-evpn-multihoming-dataplane.md`), and zebra-rs will not replicate the
tc/eBPF workarounds required to fake them there. A multihomed ES therefore
requires `system ebpf enabled`.

## Feature Matrix

| Feature | EVPN/VXLAN | EVPN/SRv6 | EVPN/MPLS |
|---|---|---|---|
| **L2 unicast (Type-2 MAC/IP)** | ✅ Kernel (SVD `external`+`vnifilter`, #1843) **and** cradle eBPF | ✅ cradle eBPF (End.DT2U) | ✅ cradle eBPF (EVI service label, `pop-l2` ILM) |
| **BUM / ingress replication (Type-3 IMET)** | ✅ Kernel zero-MAC FDB + cradle repl slots | ✅ cradle eBPF (End.DT2M) | ✅ cradle eBPF (repl slot + label imposition) |
| **MAC mobility / aging (RFC 7432 §7.7)** | ✅ | ✅ | ✅ (encap-agnostic, WatchFdb) |
| **L3 / Type-5 IP Prefix (RFC 9136)** | ✅ Symmetric IRB, L3VNI + Router's-MAC EC (zebra #1913 + cradle #119) | ✅ End.DT46/DT4/DT6 per RFC 9252 (no RMAC by design) | ✅ Reuses VPNv4/v6 L3VPN data plane (#1035–#1039) |
| **Multihoming ESI (Type-1/4, DF election)** | ✅ Control plane (shared) | ✅ Full signal set incl. Type-2 ESI (#2148/#2150/#2152) | ✅ Control plane (shared) |
| **MAC aliasing / mass-withdraw consumers** | ❌ Open (receive side) | ❌ Open — exists for VPWS only | ❌ Open |
| **Multihoming dataplane (non-DF filter, split-horizon, ES NHG, single-active)** | 🔶 **cradle-only by decision**; kernel backend stays single-homed. ✅ non-DF BUM filter: DF election (VNI as Ethernet Tag) teed as `SetEthernetSegment`/`SetEsRole`, enforced in cradle's flood loop (cradle #181, BDD `cradle_evpn_mh_df_zebra`). ✅ split-horizon / local bias (RFC 8365 §8.3.1): Type-4 peers teed as `SetEsPeers`, source VTEP resolved at decap in cradle — requires `vtep-source` = the VTEP so the Type-4 Originating IP matches the overlay source. ❌ ES NHG, single-active | 🔶 same tee (encap-agnostic; bd = VNI; SRv6 outer source) | 🔶 same tee; ❌ split horizon (no source address; ESI label) |
| **E-Line / VPWS (RFC 8214)** | ✅ Type-1 VNI + Encapsulation EC + VTEP next hop; cradle eBPF xconnect (VTEP+VNI encap, E-Line-VNI decap) | ✅ End.DX2/DX2V, VLAN scoping, MTU check, P/B multihoming (#2116) | ✅ Per-service label, no Encapsulation EC; cradle eBPF xconnect (label encap under the transport LSP, pop-to-AC decap) |
| **IPv6 underlay transport** | ✅ Kernel: zero code changes (#1850); eBPF: native v6 VTEPs incl. E-Line + `vtep-source` origination knob (cradle #168) | ✅ (native) | ✅ v6 PEs: FIB6 service-label resolution (engine) + `vtep-source` next hops; labeled static v6 routes + static-ILM v6 bindings for transport incl. pure-P transit (IS-IS SR-MPLS prefix-SIDs remain v4-only) |
| **IGMP/MLD proxy / SMET (RFC 9251)** | ✅ Incl. per-VTEP selective MDB | ✅ Control plane (shared) | ✅ Control plane (shared) |
| **Assisted Replication (RFC 9574)** | ✅ Control plane; AR-LEAF/RNVE forward natively. ❌ AR-REPLICATOR data plane deferred | ✅ Control plane (shared) | ✅ Control plane (shared) |
| **BUM segmentation (RFC 9572, Types 9/10/11)** | ✅ Control plane complete (RBR/ASBR, DF, S-PMSI) | ✅ + SR-P2MP tree offload wiring | ✅ Control plane (shared) |
| **P2MP replication tree** | — (head-end IR model) | ✅ RFC 9524 End.Replicate incl. Bud (zebra #1923 + cradle #131) | ❌ MPLS-P2MP forwarder not built |
| **ARP suppression** | ❌ Open | ❌ Open | ❌ Open |
| **Datapath BDD (CE-to-CE ping, zebra-driven)** | ✅ `cradle_evpn_vxlan_zebra*`, `cradle_vpws_vxlan_zebra`, v6-underlay twins `cradle_evpn_vxlan6_zebra` + `cradle_vpws_vxlan6_zebra` + kernel playsets | ✅ `cradle_evpn_srv6_zebra*`, `cradle_vpws_zebra` — deepest coverage | ✅ `cradle_evpn_mpls_zebra`, `cradle_vpws_mpls_zebra` (IS-IS SR-MPLS transport + pure-P transit), v6-PE twins `cradle_evpn_mpls6_zebra` + `cradle_vpws_mpls6_zebra` + P-transit `cradle_evpn_mpls6_zebra_transit` |

**Legend**: ✅ supported · ❌ not yet · — not applicable. "Control plane
(shared)" = the feature is encapsulation-agnostic in zebra-rs; the per-encap
column difference is only the forwarding plane.

## E-Line (EVPN VPWS, RFC 8214) Detail

E-Line service is implemented as EVPN VPWS: a `vpws` list under
`router bgp afi-safi evpn` (RD `router-id:evi`, RT `AS:evi`), signaled with
per-EVI Ethernet A-D (Type-1) routes and forwarded by the cradle eBPF
cross-connect datapath under all three encapsulations — SRv6 End.DX2/DX2V,
VXLAN VTEP+VNI, or an MPLS service label under the transport LSP.

| E-Line capability | Status | Notes |
|---|---|---|
| Single-homed point-to-point VPWS | ✅ | zebra #1762 (core) + #1778 (show + BDD); cradle #45 (DX2 datapath + Xconnect RPC) |
| VLAN-scoped E-Line (VLAN-based service) | ✅ | `vlan` leaf → End.DX2V, VLAN table = EVI (zebra #1782, cradle #48). CE side needs `ethtool -K … txvlan off rxvlan off` (XDP sees no offloaded tags) |
| L2-Attributes extended community (P/B/C flags + MTU) | ✅ | Attached to every VPWS Type-1 (#1779); MTU mismatch ⇒ do not bind, state `mtu-mismatch` |
| Service re-point / route-before-config reconcile | ✅ | `vpws_reconcile` re-derives remote SID from an EVPN Loc-RIB rescan |
| Multihoming origination (ESI, Primary/Backup roles) | ✅ | #2116 — `vpws` references an `ethernet-segment`; DF election per `<ESI, service instance>`; all-active ⇒ all Primary, single-active ⇒ DF Primary + Backup |
| VNI-conflict guard (VXLAN) | ✅ | A VNI already claimed on the PE — another VPWS service, an L2VNI vxlan device, a VRF's L3VNI — parks the service in `vni-conflict` (owner named in show) instead of originating; retry hooks un-park it when the owner releases the VNI |
| Remote Primary/Backup selection + per-ES A-D fast failover | ✅ | `select_remote` ranks P over B with the per-ES A-D mass-withdraw gate; failover scenarios in `bgp_evpn_vpws_multihoming.feature` |
| All-active load balancing | ❌ Open | Needs a cradle xconnect holding more than one remote endpoint |
| Control word | ❌ | C flag always 0 |
| MPLS encapsulation | ✅ | `encapsulation mpls` puts a per-service label (same dynamic block as VRF/EVI labels) in the Type-1 label field with no Encapsulation EC (RFC 8365 §5.1.3); import binds PE+label remotes; the tee drives the cradle MPLS xconnect (label imposed under the FIB-resolved transport LSP, `MPLS_OP_POP_XC` pop-to-AC decap) |
| VXLAN encapsulation | ✅ | `encapsulation vxlan` puts the service VNI (`vni` leaf, default the EVI) in the Type-1 label field with the VXLAN Encapsulation EC and VTEP next hop (RFC 8365 §6); import binds whatever encap the remote signalled; the tee drives the cradle VXLAN xconnect (VTEP+VNI encap, E-Line-VNI decap, `SetVtepSource` from the advertised next hop) |
| Datapath BDD | ✅ | Zebra-driven CE-to-CE per encap: `cradle_vpws_zebra` (SRv6), `cradle_vpws_vxlan_zebra` (VXLAN), `cradle_vpws_mpls_zebra` (MPLS, IS-IS SR-MPLS + P transit) — each untagged + VLAN-30; static twins `cradle_evpn_vpws{,_vxlan,_mpls}` |

### E-Line by Encapsulation

E-Line signaling honors the afi-safi `encapsulation`: the Type-1 carries
an End.DX2/DX2V L2-Service Prefix-SID under `srv6`, the service VNI plus
the VXLAN Encapsulation EC and VTEP next hop under `vxlan` (RFC 8365 §6),
or a per-service MPLS label with no Encapsulation EC under `mpls` (RFC
8365 §5.1.3's default). The import side classifies each remote by what
*it* signalled (SRv6 L2 Service TLV first, else VXLAN EC + label, else
no-EC label = MPLS PE+label), so a fabric can migrate between any pair of
encapsulations one PE at a time. The
cradle cross-connect data plane runs all three flavors: the tee
programs the remote endpoint encap, the local decap identity (LocalSid,
E-Line VNI, or pop-to-AC ILM) and, for VXLAN, the fabric VTEP source in
one `AddXconnect`. Every E-Line row in the matrix below is closed
except all-active load balancing and the control word.

| E-Line capability | E-Line/VXLAN | E-Line/SRv6 | E-Line/MPLS |
|---|---|---|---|
| **Per-EVI Ethernet A-D signaling (Type-1)** | ✅ VNI in the label field + VXLAN Encapsulation EC + VTEP next hop | ✅ SRv6 L2 Service TLV → End.DX2 SID | ✅ Per-service label in the label field, no Encapsulation EC (RFC 8365 §5.1.3) |
| **P2P cross-connect data plane** | ✅ cradle eBPF xconnect (`ReplTarget`-shaped maps + `VNI_F_ELINE` decap, cradle #163) | ✅ cradle eBPF xconnect (cradle #45) | ✅ cradle eBPF xconnect (`REPL_KIND_MPLS` targets + `MPLS_OP_POP_XC` decap, cradle #165) |
| **VLAN-scoped E-Line** | ✅ Inner-VID demux from the DX2V table (`VNI_F_ELINE_VLAN`) | ✅ End.DX2V, VLAN table = EVI (zebra #1782, cradle #48) | ✅ Inner-VID demux from the DX2V table (`MPLS_OP_POP_XC_VLAN`) |
| **L2-Attributes EC (P/B/C flags + MTU)** | ✅ On every VPWS Type-1 | ✅ On every VPWS Type-1 (#1779) | ✅ On every VPWS Type-1 |
| **Multihoming origination (ESI, P/B roles)** | ✅ Encap-agnostic (#2116; `bgp_evpn_vpws_vxlan_multihoming` proves failover re-binds VTEP *and* per-PE VNI) | ✅ DF per `<ESI, service instance>` (#2116) | ✅ Encap-agnostic |
| **Remote P/B selection + per-ES fast failover** | ✅ Encap-agnostic | ✅ | ✅ Encap-agnostic |
| **All-active load balancing** | ❌ | ❌ Open (needs multi-SID xconnect) | ❌ |
| **Control word** | — (no control word in VXLAN) | — (no control word in SRv6) | ❌ C flag always 0 |
| **Datapath BDD** | ✅ `cradle_vpws_vxlan_zebra`, `cradle_evpn_vpws_vxlan` (+ signaling `bgp_evpn_vpws_vxlan`) | ✅ `cradle_vpws_zebra`, `cradle_evpn_vpws` | ✅ `cradle_vpws_mpls_zebra` (IS-IS SR-MPLS + P transit), `cradle_evpn_vpws_mpls` (+ signaling `bgp_evpn_vpws_mpls`) |

## Per-Encapsulation Summary

- **VXLAN**: mature, with both kernel-native and eBPF data planes; the only
  encapsulation with kernel forwarding and the full multicast-optimization
  stack (SMET per-VTEP delivery, AR leaf/RNVE). VPWS complete
  (#2190/#2192/#2193 + cradle #163/#164) with the VNI-conflict guard and
  multihoming failover proofs.
- **SRv6**: complete L2 + L3 + VPWS + P2MP replication on the eBPF data
  plane, with the deepest BDD coverage (coverage plan phases 0–3 closed
  2026-07-28).
- **MPLS**: L3 (Type-5) complete for a long time via L3VPN reuse; L2 made
  real by the cradle eBPF data plane (`cradle_evpn_mpls_zebra` proves
  IS-IS SR-MPLS transport + BGP EVPN service labels end to end); VPWS
  complete (#2196/#2198 + cradle #165/#166 — dynamic per-service labels,
  pop-to-AC ILM, `cradle_vpws_mpls_zebra` e2e). P2MP replication remains
  the gap.

With the E-LINE arcs closed 2026-08-02, VPWS is the first EVPN service
running end to end over all three encapsulations, mixed per direction; the
per-service E-Line gaps left open everywhere are all-active load balancing
and the (MPLS-only) control word.
