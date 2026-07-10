# Playsets

Playsets are self-contained demo labs for zebra-rs — a simple, easy way to
experience cutting-edge routing technology. Each one builds a small network out
of Linux network namespaces connected by veth pairs, runs a zebra-rs daemon in
every node, injects per-node YAML configuration with `vtyctl apply -f
<node>.yaml`, and walks through a feature in its README with real command output
captured from a live run.

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

## SRv6 & SR-MPLS with TI-LFA fast-reroute

Seven labs, one topology — the RFC 9855 example network with two edge hosts
attached — covering the IGP x data-plane matrix. Every walkthrough follows
the same arc: examine SR routing at the source, enable
`fast-reroute ti-lfa` at runtime, force the repair into use with
`backup-as-primary`, and capture the repair on the wire, including the
protected edge-to-edge traffic.

| playset | IGP | data plane | edge service |
|:--|:--|:--|:--|
| [isis-srv6-classic](isis-srv6-classic/README.md) | IS-IS | SRv6, classic RFC 8986 SIDs (RFC 9352) | RFC 9252 iBGP IPv6-unicast with End.DT6 service SIDs |
| [isis-srv6-usid](isis-srv6-usid/README.md) | IS-IS | SRv6, uSID / NEXT-C-SID (RFC 9800) | RFC 9252 iBGP IPv6-unicast with End.DT6 service SIDs |
| [ospfv3-srv6-classic](ospfv3-srv6-classic/README.md) | OSPFv3 (area 0) | SRv6, classic RFC 8986 SIDs (RFC 9513) | RFC 9252 iBGP IPv6-unicast with End.DT6 service SIDs |
| [ospfv3-srv6-usid](ospfv3-srv6-usid/README.md) | OSPFv3 (area 0) | SRv6, uSID / NEXT-C-SID (RFC 9800) | RFC 9252 iBGP IPv6-unicast with End.DT6 service SIDs |
| [isis-srmpls](isis-srmpls/README.md) | IS-IS | SR-MPLS (SRGB 16000 / SRLB 15000) | recursive IPv4 statics inheriting the SR label stack |
| [ospfv2-srmpls](ospfv2-srmpls/README.md) | OSPFv2 (area 0) | SR-MPLS (RFC 8665 extended LSAs) | recursive IPv4 statics inheriting the SR label stack |
| [ospfv3-srmpls](ospfv3-srmpls/README.md) | OSPFv3 (area 0) | SR-MPLS over IPv6 (RFC 8666, NP-flag / no PHP) | recursive IPv6 statics inheriting the SR label stack |

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
the same IPv4 tenant payload on `172.16.10.0/24`. Start with `vxlan4` (the
base) and add one dimension at a time.

| playset | underlay | tenancy | what it adds |
|:--|:--|:--|:--|
| [bgp-evpn-vxlan4](bgp-evpn-vxlan4/README.md) | IPv4 | single VNI | the base — one L2 segment stretched across two VTEPs, hosts pinging at `ttl=64` |
| [bgp-evpn-vxlan6](bgp-evpn-vxlan6/README.md) | **IPv6** | single VNI | IPv6 VTEP endpoints, next hops, PMSI, and FDB `dst`, while the RD stays IPv4 — an IPv4 payload across an IPv6-only core |
| [bgp-evpn-vxlan4-multi](bgp-evpn-vxlan4-multi/README.md) | IPv4 | **two VNIs** | three VTEPs, one serving both VNIs; per-VNI RD/RT isolation — hosts in different VNIs share a subnet yet cannot reach each other |
| [bgp-evpn-vxlan6-multi](bgp-evpn-vxlan6-multi/README.md) | **IPv6** | **two VNIs** | both dimensions at once — per-VNI IPv6 next hops/PMSI each on its own underlay link, IPv4 RDs, cross-VNI isolation |

The four EVPN labs reuse the same namespace names (`vtep1`..`vtep3`,
`h1`..`h4`), so bring up only one at a time — `up.sh` sweeps leftovers of
the same names first.

## BGP Inter-AS L3VPN

Two providers, one VPN — the RFC 4364 §10 options for handing L3VPN
routes across an AS boundary.

| playset | scheme |
|:--|:--|
| [interas-option-a](interas-option-a/README.md) | Option A — back-to-back VRFs: a dedicated link and a plain eBGP IPv4 session per customer between the ASBRs, MPLS never crossing the boundary. Two ASes with independent RD/RT spaces, two customers with deliberately overlapping addressing, and a three-point capture of one ping riding MPLS → plain IP → MPLS |
| [interas-option-b](interas-option-b/README.md) | Option B — eBGP VPNv4 between ASBRs (topology template; walkthrough to follow) |
| [interas-option-c](interas-option-c/README.md) | Option C — multihop eBGP VPNv4 between route reflectors, labeled transport between ASes (topology template; walkthrough to follow) |

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
