# BGP EVPN Type-5 (IP Prefix Routes)

zebra-rs implements **EVPN Type-5 (IP Prefix) routes** as specified in
RFC 9136. Type-5 carries an IP prefix across an EVPN as an L3VPN-style
service — it is, in effect, an alternative NLRI *encoding* of the same
per-VRF IP routing that [VPNv4 / VPNv6 L3VPN](ch-02-04-bgp-l3vpn.md)
provides. DC fabrics commonly prefer the EVPN encoding because one
address family (`l2vpn evpn`) then carries both the L2 service (Type-2 /
Type-3, over [VXLAN](ch-00-03-vxlan-configuration.md), SRv6 or
[MPLS](ch-02-40-bgp-evpn-mpls.md)) and the L3 service (Type-5).

Because Type-5 reuses the existing L3VPN control- and data-plane, the
two ends of a VPN flow map exactly as they do for VPNv4 / VPNv6:

* the **egress PE** binds a per-VRF forwarding identifier — an **MPLS
  service label** (MPLS underlay), an **SRv6 End.DT46 SID** (SRv6
  underlay), or a **tenant L3VNI** (VXLAN symmetric IRB, RFC 8365) — and
  programs a decap into the VRF table (an `RTA` MPLS-`DecapVrf` ILM, a
  `seg6local` End.DT46 entry, or the L3VNI's vxlan device);
* the **ingress PE** imports a received Type-5 route whose route-targets
  match a local VRF and installs it with a `{transport, service}` MPLS
  label-push next-hop, an SRv6 **H.Encap** next-hop toward the remote
  SID, or a VXLAN encap toward the remote VTEP with the inner Ethernet
  destination rewritten to the egress PE's router-MAC (RFC 9135).

The forwarding identifier rides in the Type-5 NLRI's label field (the
MPLS service label, or the L3VNI under VXLAN) or in the BGP
**Prefix-SID** attribute's SRv6 L3 Service TLV (SRv6, label 0) — the
same attributes the VPNv4 / VPNv6 paths use.

## Configuration

Type-5 advertisement is opt-in per VRF via the **`evpn`** block, named
to match the `evpn` address family. It reuses the VRF's existing `rd`,
route-targets, and `encapsulation`; no separate RD / RT / VNI is
introduced:

```
set router bgp vrf red rd 65000:100
set router bgp vrf red encapsulation mpls
set router bgp vrf red afi-safi ipv4 network 10.0.0.0/24
set router bgp vrf red evpn advertise-ipv4 true
set router bgp vrf red evpn advertise-ipv6 true
```

* `advertise-ipv4` / `advertise-ipv6` advertise the VRF's IPv4 / IPv6
  unicast routes as EVPN Type-5 routes. Both default to `false`.
* `rd` is required (Type-5 carries a Route Distinguisher).
* `encapsulation {mpls|srv6|vxlan}` selects the data plane — `mpls` uses
  the per-VRF service label and `srv6` the VRF's End.DT46 SID carved
  from the global `segment-routing` locator, exactly as for VPNv4 /
  VPNv6. `vxlan` is the **symmetric-IRB** mode (RFC 8365): set `evpn
  l3vni <vni>` to the tenant L3VNI carried in the NLRI's label field —
  it must match an `l3vni` on a local vxlan device bound to this VRF —
  and the route carries this PE's router-MAC in the Router's-MAC
  extended community (RFC 9135; `evpn router-mac` overrides it,
  defaulting to the VRF master device's MAC):

  ```
  set router bgp vrf blue rd 65000:200
  set router bgp vrf blue encapsulation vxlan
  set router bgp vrf blue evpn advertise-ipv4 true
  set router bgp vrf blue evpn l3vni 4000
  ```

A neighbor must negotiate the L2VPN/EVPN address family to exchange
Type-5 routes:

```
set router bgp neighbor 10.0.0.1 remote-as 65001
set router bgp neighbor 10.0.0.1 afi-safi evpn enabled true
```

### Composition with VPNv4 / VPNv6

Enabling the `evpn` block does **not** disable VPNv4 / VPNv6. A VRF with
both an RD (for VPNv4/v6) and `evpn advertise-*` set populates both the
VPNv4/v6 and the EVPN Loc-RIB; each peer receives only the encoding it
negotiated — a `vpnv4` peer gets VPNv4, an `evpn` peer gets Type-5. This
makes Type-5 additive and lets a route reflector or PE speak both during
a migration.

## Data plane

| Underlay | NLRI label | BGP next-hop | Ingress install | Egress decap |
|---|---|---|---|---|
| **MPLS** | per-VRF service label | `vtep-source`, else router-id | `{transport, service}` label push | MPLS `DecapVrf` ILM |
| **SRv6** | 0 | PE locator | H.Encap to End.DT46 SID | `seg6local` End.DT46 |
| **VXLAN (IRB)** | tenant L3VNI | local VTEP (IPv4) | VXLAN encap + inner DMAC ← egress router-MAC | L3VNI vxlan device into the VRF |

The MPLS and SRv6 rows are the *same* mechanisms VPNv4 / VPNv6 already
use — Type-5 simply arrives in a different NLRI. Recursive next-hop
resolution (NHT) gates every install: a Type-5 route only programs the
VRF FIB once its PE next-hop resolves over the underlay, and re-installs
if that underlay reroutes.

Two address-family notes:

* Under **MPLS**, the afi-safi `vtep-source` names the address the
  Type-5 advertises as next hop (the router-id fallback is IPv4-only),
  and the transport stack resolves through the v4 or v6 FIB by that
  address's family — so a v6 `vtep-source` runs Type-5 over an
  **IPv6-only core**, the same three pieces as the L2 services (see
  [IPv6 PEs](ch-02-40-bgp-evpn-mpls.md#ipv6-pes)).
* The **symmetric-IRB VXLAN path is IPv4-VTEP-only** (the inner prefix
  may be v4 or v6, the outer VTEP is always IPv4) — unlike the L2
  services, which also run over native v6 VTEPs on the eBPF data plane.

> **Note** — this is the **L3** EVPN service. EVPN's **L2** services
> (Type-2 MAC/IP, Type-3 inclusive-multicast) are documented separately and
> run over VXLAN, SRv6, or MPLS. EVPN-over-MPLS *L2* is not forwardable by
> the Linux kernel — it has no action that pops a label and hands the frame
> to a bridge — so it needs the cradle eBPF data plane; see
> [EVPN over MPLS](ch-02-40-bgp-evpn-mpls.md).

## Verification

`show bgp evpn` lists Type-5 routes with the
`[5]:[EthTag]:[IPlen]:[IP]` prefix form alongside any Type-2 / Type-3
routes. On the ingress PE, an imported Type-5 route appears in its VRF
table as a normal IP route whose next-hop is the MPLS label-push (check
`ip -f mpls route` for the per-VRF decap label) or the SRv6 H.Encap
(`ip -6 route` shows `encap seg6 ... segs <remote-SID>`). CE-facing
routes remain plain.
