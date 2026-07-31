# EVPN Support Status by Encapsulation

Status as of 2026-07-31.

A framing fact that applies to all three encapsulations: the EVPN control
plane (route types 1–6 and 9–11, ESI multihoming with DF election, MAC
mobility) is shared and encapsulation-agnostic in zebra-rs. What differs per
encapsulation is the data plane — the Linux kernel natively forwards only
VXLAN, so all SRv6-L2 and MPLS-L2 forwarding runs in the cradle-rs eBPF
datapath, driven from zebra-rs via the FibHandle tee.

## Feature Matrix

| Feature | EVPN/VXLAN | EVPN/SRv6 | EVPN/MPLS |
|---|---|---|---|
| **L2 unicast (Type-2 MAC/IP)** | ✅ Kernel (SVD `external`+`vnifilter`, #1843) **and** cradle eBPF | ✅ cradle eBPF (End.DT2U) | ✅ cradle eBPF (EVI service label, `pop-l2` ILM) |
| **BUM / ingress replication (Type-3 IMET)** | ✅ Kernel zero-MAC FDB + cradle repl slots | ✅ cradle eBPF (End.DT2M) | ✅ cradle eBPF (repl slot + label imposition) |
| **MAC mobility / aging (RFC 7432 §7.7)** | ✅ | ✅ | ✅ (encap-agnostic, WatchFdb) |
| **L3 / Type-5 IP Prefix (RFC 9136)** | ✅ Symmetric IRB, L3VNI + Router's-MAC EC (zebra #1913 + cradle #119) | ✅ End.DT46/DT4/DT6 per RFC 9252 (no RMAC by design) | ✅ Reuses VPNv4/v6 L3VPN data plane (#1035–#1039) |
| **Multihoming ESI (Type-1/4, DF election)** | ✅ Control plane (shared) | ✅ Full signal set incl. Type-2 ESI (#2148/#2150/#2152) | ✅ Control plane (shared) |
| **MAC aliasing / mass-withdraw consumers** | ❌ Open (receive side) | ❌ Open — exists for VPWS only | ❌ Open |
| **E-Line / VPWS (RFC 8214)** | 🟡 Signaling ✅ (Type-1 VNI + Encapsulation EC + VTEP next hop); cradle xconnect datapath open | ✅ End.DX2/DX2V, VLAN scoping, MTU check, P/B multihoming (#2116) | ❌ SRv6-only today |
| **IPv6 underlay transport** | ✅ Zero code changes (#1850) | ✅ (native) | — (IS-IS SR-MPLS underlay) |
| **IGMP/MLD proxy / SMET (RFC 9251)** | ✅ Incl. per-VTEP selective MDB | ✅ Control plane (shared) | ✅ Control plane (shared) |
| **Assisted Replication (RFC 9574)** | ✅ Control plane; AR-LEAF/RNVE forward natively. ❌ AR-REPLICATOR data plane deferred | ✅ Control plane (shared) | ✅ Control plane (shared) |
| **BUM segmentation (RFC 9572, Types 9/10/11)** | ✅ Control plane complete (RBR/ASBR, DF, S-PMSI) | ✅ + SR-P2MP tree offload wiring | ✅ Control plane (shared) |
| **P2MP replication tree** | — (head-end IR model) | ✅ RFC 9524 End.Replicate incl. Bud (zebra #1923 + cradle #131) | ❌ MPLS-P2MP forwarder not built |
| **ARP suppression** | ❌ Open | ❌ Open | ❌ Open |
| **Datapath BDD (CE-to-CE ping, zebra-driven)** | ✅ `cradle_evpn_vxlan_zebra*` + kernel playsets | ✅ `cradle_evpn_srv6_zebra*`, `cradle_vpws_zebra` — deepest coverage | ✅ `cradle_evpn_mpls_zebra` (IS-IS SR-MPLS transport + pure-P transit) |

**Legend**: ✅ supported · ❌ not yet · — not applicable. "Control plane
(shared)" = the feature is encapsulation-agnostic in zebra-rs; the per-encap
column difference is only the forwarding plane.

## E-Line (EVPN VPWS, RFC 8214) Detail

E-Line service is implemented as EVPN VPWS: a `vpws` list under
`router bgp afi-safi evpn` (RD `router-id:evi`, RT `AS:evi`), signaled with
per-EVI Ethernet A-D (Type-1) routes and forwarded by the cradle eBPF
datapath via SRv6 End.DX2 / End.DX2V cross-connects.

| E-Line capability | Status | Notes |
|---|---|---|
| Single-homed point-to-point VPWS | ✅ | zebra #1762 (core) + #1778 (show + BDD); cradle #45 (DX2 datapath + Xconnect RPC) |
| VLAN-scoped E-Line (VLAN-based service) | ✅ | `vlan` leaf → End.DX2V, VLAN table = EVI (zebra #1782, cradle #48). CE side needs `ethtool -K … txvlan off rxvlan off` (XDP sees no offloaded tags) |
| L2-Attributes extended community (P/B/C flags + MTU) | ✅ | Attached to every VPWS Type-1 (#1779); MTU mismatch ⇒ do not bind, state `mtu-mismatch` |
| Service re-point / route-before-config reconcile | ✅ | `vpws_reconcile` re-derives remote SID from an EVPN Loc-RIB rescan |
| Multihoming origination (ESI, Primary/Backup roles) | ✅ | #2116 — `vpws` references an `ethernet-segment`; DF election per `<ESI, service instance>`; all-active ⇒ all Primary, single-active ⇒ DF Primary + Backup |
| Remote Primary/Backup selection + per-ES A-D fast failover | ✅ | `select_remote` ranks P over B with the per-ES A-D mass-withdraw gate; failover scenarios in `bgp_evpn_vpws_multihoming.feature` |
| All-active load balancing | ❌ Open | Needs a cradle xconnect holding more than one remote SID |
| Control word | ❌ | C flag always 0 |
| MPLS encapsulation | ❌ | `evpn_vpws_sid` reads only End.DX2/DX2V — SRv6-only |
| VXLAN encapsulation | 🟡 | Signaling complete: `encapsulation vxlan` puts the service VNI (`vni` leaf, default the EVI) in the Type-1 label field with the VXLAN Encapsulation EC and VTEP next hop (RFC 8365 §6); import binds whatever encap the remote signalled. Cradle xconnect datapath open |
| Datapath BDD | ✅ | `cradle_vpws_zebra` (untagged + VLAN-30 E-Line, CE-to-CE), `cradle_evpn_vpws` (static) |

### E-Line by Encapsulation

E-Line signaling honors the afi-safi `encapsulation`: under `vxlan` the
Type-1 carries the service VNI in its label field with the VXLAN
Encapsulation EC and the VTEP next hop (RFC 8365 §6), and the import side
classifies each remote by what *it* signalled (SRv6 L2 Service TLV first,
else VXLAN EC + label), so a fabric can migrate one PE at a time. The
cradle cross-connect data plane is still SRv6-only — the VXLAN xconnect
tee (remote VTEP+VNI encap, VNI-to-AC decap) is the open half. MPLS VPWS
originates/consumes nothing yet (under `encapsulation mpls` a VPWS still
signals SRv6).

| E-Line capability | E-Line/VXLAN | E-Line/SRv6 | E-Line/MPLS |
|---|---|---|---|
| **Per-EVI Ethernet A-D signaling (Type-1)** | ✅ VNI in the label field + VXLAN Encapsulation EC + VTEP next hop | ✅ SRv6 L2 Service TLV → End.DX2 SID | ❌ Type-1 MPLS label field not originated/consumed |
| **P2P cross-connect data plane** | ❌ Cradle `Xconnect` has no VXLAN flavor yet | ✅ cradle eBPF xconnect (cradle #45) | ❌ Not built (cradle MPLS L2 covers E-LAN, not xconnect) |
| **VLAN-scoped E-Line** | 🟡 Signaling (`vlan` scoping is a local AC property); datapath open | ✅ End.DX2V, VLAN table = EVI (zebra #1782, cradle #48) | ❌ |
| **L2-Attributes EC (P/B/C flags + MTU)** | ✅ On every VPWS Type-1 | ✅ On every VPWS Type-1 (#1779) | ❌ No service to attach to |
| **Multihoming origination (ESI, P/B roles)** | ✅ Encap-agnostic (#2116) | ✅ DF per `<ESI, service instance>` (#2116) | ❌ |
| **Remote P/B selection + per-ES fast failover** | ✅ Encap-agnostic | ✅ | ❌ |
| **All-active load balancing** | ❌ | ❌ Open (needs multi-SID xconnect) | ❌ |
| **Control word** | — (no control word in VXLAN) | — (no control word in SRv6) | ❌ C flag always 0 |
| **Datapath BDD** | ❌ (signaling BDD: `bgp_evpn_vpws_vxlan`) | ✅ `cradle_vpws_zebra`, `cradle_evpn_vpws` | ❌ |

## Per-Encapsulation Summary

- **VXLAN**: mature, with both kernel-native and eBPF data planes; the only
  encapsulation with kernel forwarding and the full multicast-optimization
  stack (SMET per-VTEP delivery, AR leaf/RNVE).
- **SRv6**: complete L2 + L3 + VPWS + P2MP replication on the eBPF data
  plane, with the deepest BDD coverage (coverage plan phases 0–3 closed
  2026-07-28).
- **MPLS**: L3 (Type-5) complete for a long time via L3VPN reuse; L2
  recently made real by the cradle eBPF data plane (`cradle_evpn_mpls_zebra`
  proves IS-IS SR-MPLS transport + BGP EVPN service labels end to end);
  VPWS and P2MP replication remain the gaps.
