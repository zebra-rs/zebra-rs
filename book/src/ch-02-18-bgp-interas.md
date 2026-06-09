# Inter-AS L3VPN

A BGP/MPLS L3VPN ([RFC 4364](https://www.rfc-editor.org/rfc/rfc4364))
normally lives inside a single autonomous system: the PE routers run
iBGP (directly or via a route reflector), and an IGP with an MPLS
transport (LDP or SR-MPLS) glues the PE loopbacks together. *Inter-AS*
L3VPN is the case where the two ends of a VPN sit in **different**
autonomous systems — two providers, or two regions of one provider that
run separate IGPs — and the VPN must cross the AS boundary at the
Autonomous System Boundary Routers (ASBRs).

RFC 4364 §10 describes three standard ways to carry VPN routes across
that boundary, plus a widely-deployed vendor hybrid (**Option AB**):

| Option | How VPN routes cross | VPN state on the ASBRs | Transport LSP |
|---|---|---|---|
| **A** (§10a) | back-to-back VRFs; one (sub)interface per VPN between the ASBRs | full — one VRF per VPN | terminates at each ASBR |
| **B** (§10b) | MP-eBGP VPNv4/VPNv6 between the ASBRs | per-VPN-route (the ASBRs hold and re-advertise every VPN prefix) in the **global** table | terminates at each ASBR |
| **C** (§10c) | MP-eBGP VPNv4/VPNv6 directly (multihop) between the PEs (or RRs); the ASBRs exchange only **labeled IPv4/IPv6** (BGP-LU) for the PE loopbacks | **none** — the ASBRs hold no VPN routes | a single end-to-end LSP from ingress PE to egress PE |
| **AB** (hybrid) | a **single** MP-eBGP VPNv4/VPNv6 session between the ASBRs (as in B) | per-VPN — the ASBRs hold every VPN prefix in a **VRF** (as in A) and forward per-VRF | terminates at each ASBR |

The options trade off ASBR scaling against operational coupling. Option
A needs no MPLS on the inter-AS link but burns a (sub)interface and a
VRF per VPN. Option B keeps the ASBRs in the VPN control plane (and the
VPN data plane) but needs no per-VPN VRF — the ASBRs hold every VPN route
in their global VPNv4 table and label-swap it across the boundary.
**Option C** pushes both out: the ASBRs only need to make the remote PE
loopbacks reachable — and labeled — so a single LSP runs end to end and
the VPN routes pass over the top, transparent to the ASBRs. **Option AB**
splits the difference between A and B: a *single* MP-eBGP session carries
every VPN (B's scaling), but the ASBRs still keep a per-VPN VRF and
forward through it (A's per-VPN control and security), so it needs
neither a per-VPN interface nor a transparent label swap.

> **Implemented today:** all four —
> [Option A](ch-02-20-bgp-interas-option-a.md) (back-to-back VRFs),
> [Option B](ch-02-21-bgp-interas-option-b.md) (VPNv4 between ASBRs),
> [Option C](ch-02-19-bgp-interas-option-c.md) (BGP-LU between ASBRs), and
> [Option AB](ch-02-22-bgp-interas-option-ab.md) (single VPNv4 session +
> per-VRF forwarding) — each with an SR-MPLS transport inside the AS.
