# Playsets

Playsets are self-contained demo labs for zebra-rs — a simple, easy way to
experience cutting-edge routing technology. Each one builds a small network out
of Linux network namespaces connected by veth pairs, runs a zebra-rs daemon in
every node, injects per-node YAML configuration with `vtyctl apply -f
<node>.yaml`, and walks through a feature in its README with real command output
captured from a live run.

Sixteen walkthroughs in three series — [SR-MPLS & SRv6 with TI-LFA
fast-reroute](#sr-mpls--srv6-with-ti-lfa-fast-reroute) (seven labs, one
topology, the IGP × data-plane matrix), [BGP EVPN
VXLAN](#bgp-evpn-vxlan) (four labs, underlay × tenancy), and [BGP
Inter-AS L3VPN](#bgp-inter-as-l3vpn) (five labs, one border model at a
time) — each series sharing one base topology so the labs diff cleanly
against each other.

## Running a playset

``` shell
$ cd <playset-directory>
$ ./up.sh        # create namespaces + links, start zebra-rs, apply configs
$ ./down.sh      # stop the daemons and delete the namespaces
```

Log in to any node's industry-standard CLI shell:

``` shell
$ sudo ip netns exec <node> vty
s>show ip route
```

Every node sets `system hostname`, so the vty prompt shows which node you
are on (`s>`, `n1>`, `e1>`, ...; `#` when in admin/configure mode). Regular
Linux tooling works inside the namespaces too — `ip route`, `tcpdump`,
`ping` — and the READMEs use both views side by side.

The daemon and CLI binaries are resolved from `target/debug/` when built,
falling back to the installed ones on `PATH`. Each playset writes its
runtime state (`*.log`, `*.pid`) into its own directory; those files are
gitignored.

> **One at a time**: the TI-LFA playsets share the same topology and
> namespace names (`s`, `n1`..`n3`, `r1`..`r3`, `d`, `e1`, `e2`), so bring
> up only one of them at once — `up.sh` tears down leftovers of the same
> names first.

## SR-MPLS & SRv6 with TI-LFA fast-reroute

Seven labs, one topology — the RFC 9855 example network with two edge hosts
attached — covering the IGP x data-plane matrix. Every walkthrough follows
the same arc: examine SR routing at the source, enable
`fast-reroute ti-lfa` at runtime, force the repair into use with
`backup-as-primary`, and capture the repair on the wire, including the
protected edge-to-edge traffic.

Rows are the data plane, columns the IGP:

| | IS-IS | OSPFv2 | OSPFv3 |
|:--|:--|:--|:--|
| **SR-MPLS** | [isis-srmpls](isis-srmpls/README.md) | [ospfv2-srmpls](ospfv2-srmpls/README.md) | [ospfv3-srmpls](ospfv3-srmpls/README.md) |
| **SRv6 (classic)** | [isis-srv6-classic](isis-srv6-classic/README.md) | — | [ospfv3-srv6-classic](ospfv3-srv6-classic/README.md) |
| **SRv6 (uSID)** | [isis-srv6-usid](isis-srv6-usid/README.md) | — | [ospfv3-srv6-usid](ospfv3-srv6-usid/README.md) |

The two **SRv6** rows differ only in SID encoding — **classic** RFC 8986
(RFC 9352 for IS-IS, RFC 9513 for OSPFv3) versus **uSID** / NEXT-C-SID
(RFC 9800) — and each lab carries an RFC 9252 iBGP IPv6-unicast service with
End.DT6 SIDs. The **SR-MPLS** labs (SRGB 16000 / SRLB 15000; RFC 8665
extended LSAs for OSPFv2, RFC 8666 NP-flag / no-PHP for OSPFv3 over IPv6)
carry recursive IP statics that inherit the SR label stack. There is no
OSPFv2 SRv6 lab.

Some cross-cutting themes to look for:

* **SR-MPLS vs SRv6 repair encoding.** The MPLS repairs terminate at the
  destination's own node SID (the label stacks end in e.g. `16800`), while
  the SRv6 repairs are SRH insertions whose final segment is the packet's
  original destination — the same guarantee, achieved two different ways.
  Compare the `repair-list` outputs of `ospfv2-srmpls` and
  `ospfv3-srv6-classic` side by side.
* **How edge traffic gets protected.** Label inheritance through recursive
  statics (SR-MPLS), versus a BGP service riding a protected locator
  (SRv6) — both walkthroughs end with a wire capture of protected
  edge-to-edge traffic (a 4-label stack in one world, a double SRH in the
  other).
* **`backup-as-primary`.** Every lab uses this knob to pin live traffic
  onto the TI-LFA repair while every link stays up, which makes the repair
  path observable with plain `tcpdump`.

## BGP EVPN VXLAN

Four labs across two axes — **underlay transport** (IPv4 vs IPv6) and
**tenancy** (single VNI vs two isolated VNIs). All share the same EVPN
control plane (Type-2 MAC + Type-3 IMET, ingress replication) driving the
kernel's single-VXLAN-device (`external` / `vnifilter`) data plane, and
the same IPv4 tenant payload on `172.16.10.0/24`.

Rows are the tenancy, columns the underlay transport:

| | IPv4 | IPv6 |
|:--|:--|:--|
| **single VNI** | [bgp-evpn-vxlan4](bgp-evpn-vxlan4/README.md) | [bgp-evpn-vxlan6](bgp-evpn-vxlan6/README.md) |
| **two VNIs** | [bgp-evpn-vxlan4-multi](bgp-evpn-vxlan4-multi/README.md) | [bgp-evpn-vxlan6-multi](bgp-evpn-vxlan6-multi/README.md) |

`vxlan4` is the base; move right to swap the underlay to **IPv6** (IPv6 VTEP
endpoints, next hops, PMSI, and FDB `dst`, while the RD stays IPv4), and move
down to add a **second isolated VNI** (three VTEPs, one serving both; per-VNI
RD/RT — hosts in different VNIs share a subnet yet cannot reach each other).

The four EVPN labs reuse the same namespace names (`vtep1`..`vtep3`,
`h1`..`h4`), so bring up only one at a time — `up.sh` sweeps leftovers of
the same names first.

## BGP Inter-AS L3VPN

Two providers, one VPN — the RFC 4364 §10 options (plus Cisco's AB
hybrid) for handing L3VPN routes across an AS boundary. All the labs run
the same ten routers, customers, and overlapping addressing (the RR
variant adds two route reflectors); only the border model changes:

|                                 | Option A       | Option B            | Option AB              | Option C       |
|:--------------------------------|:---------------|:--------------------|:-----------------------|:---------------|
| labels crossing the border      | 0 (plain IP)   | 1 (VPN)             | 1 (VPN)                | 2 (LU + VPN)   |
| VPN routes on the ASBR          | all (in VRFs)  | all (global VPNv4)  | all (in transit VRFs)  | none           |
| ASBR state scales with          | customers      | VPN routes          | customers              | PEs            |

(`interas-option-c-rr` shares Option C's column — it changes only the
control plane, swapping the direct PE-to-PE session for Cisco's
route-reflector design.)

Read them in order — A, B, AB, C, C-RR — and diff each lab against the
previous one: the CEs never change, the PEs barely change, and the whole
story lives in the ASBRs. The labs share namespace names
(`ce1`..`ce4`, `pe1`, `p1`, `asbr1`, `asbr2`, `p2`, `pe2`, plus
`rr1`/`rr2` in the RR variant), so bring up only one at a time.

| playset | scheme |
|:--|:--|
| [interas-option-a](interas-option-a/README.md) | Option A — back-to-back VRFs: a dedicated link and a plain eBGP IPv4 session per customer between the ASBRs, MPLS never crossing the boundary. Two ASes with independent RD/RT spaces, two customers with deliberately overlapping addressing, and a three-point capture of one ping riding MPLS → plain IP → MPLS |
| [interas-option-b](interas-option-b/README.md) | Option B — one eBGP VPNv4 session between the ASBRs carries every customer, MPLS crossing the boundary as a single label switch. Same lab as Option A with only the border changed: no VRFs on the ASBRs, coordinated RTs (independent RDs), per-route swap ILMs, and the far AS's RDs relayed unchanged |
| [interas-option-ab](interas-option-ab/README.md) | Option AB — Cisco's hybrid: per-customer transit VRFs at each border (like A, but with no interfaces or sessions in them) riding one eBGP VPNv4 session (like B). Each ASBR terminates the VPN label into the customer's VRF, makes an IP routing decision, and re-originates under its own RD with a clean RT — the per-VPN policy point B lost, without A's per-customer sessions |
| [interas-option-c](interas-option-c/README.md) | Option C — the ASBRs exchange only labeled PE loopbacks (BGP-LU) and hold zero VPN state; the PEs peer VPNv4 directly over a multihop eBGP session, and a three-label stack (SR transport, BGP-LU, VPN) rides from PE to PE — two labels crossing the boundary, completing the 0/1/2-label arc across A/B/C |
| [interas-option-c-rr](interas-option-c-rr/README.md) | Option C, RR-based — Cisco's reference design: each AS adds a route reflector, the RRs exchange VPNv4 over a multihop eBGP session with `next-hop-unchanged`, and the PEs peer only with their local RR. Same data plane as the direct-PE lab; the RRs hold every VPN route and forward none of the traffic |

## Directory layout

```
playset/
├── lib/          # shared bash harness (namespaces, links, daemon lifecycle)
├── images/       # topology diagrams referenced by the READMEs
└── <playset>/    # topology.sh + per-node *.yaml + up.sh / down.sh + README.md
```

A playset directory only needs three things: a `topology.sh` declaring
namespaces and veth links, one YAML config per node, and the two wrapper
scripts sourcing `lib/`. Copy an existing playset as a starting point.
