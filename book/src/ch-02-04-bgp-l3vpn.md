# BGP/MPLS L3VPN and Per-VRF Labels

zebra-rs implements BGP/MPLS IP VPNs as specified in RFC 4364. A
Provider Edge (PE) router keeps customer routes in per-VRF routing
tables, advertises them to remote PEs as VPNv4 / VPNv6 routes carrying
a Route Distinguisher and an MPLS service label, and forwards VPN
traffic to the egress PE over an MPLS transport tunnel (an IS-IS / OSPF
prefix-SID in an SR-MPLS core).

This chapter focuses on the per-VRF label: how it is allocated,
advertised, and programmed into the forwarding plane. The companion
control-plane machinery — route-target import/export, recursive
next-hop resolution, and FIB arbitration between imported and
CE-learned routes — is summarised where it bears on the data path. The
PE-CE side — which routing protocol runs to the customer, and how its
routes are redistributed into and out of the VPN — is covered in
[L3VPN PE-CE Routing Protocols](ch-02-36-bgp-l3vpn-pe-ce.md).

## The moving parts

A working L3VPN PE on zebra-rs touches two configuration trees:

* the **VRF** (under `vrf <name>`) creates the Linux VRF master device
  and its routing table, and carries the route-target import/export
  sets that decide which VPN routes land in the VRF;
* the **per-VRF BGP instance** (under `router bgp vrf <name>`) runs the
  PE↔CE sessions, originates the VRF's local routes, and owns the
  Route Distinguisher and the per-VRF MPLS label.

```
vrf vrf1 {
  ipv4 {
    route-target {
      import 65000:1;
      export 65000:1;
    }
  }
}

router bgp {
  vrf vrf1 {
    rd 65000:1;
    label-mode per-vrf;
    neighbor 10.100.0.2 {
      remote-as 65001;
    }
    afi-safi ipv4 {
      network 192.168.5.0/24;
    }
  }
}
```

| Config | Meaning |
|---|---|
| `vrf <name>` | Create the VRF master device + kernel table |
| `vrf <name> {ipv4,ipv6} route-target import <RT>` | Pull matching VPN routes into the VRF |
| `vrf <name> {ipv4,ipv6} route-target export <RT>` | Tag this VRF's exported routes with `<RT>` |
| `router bgp vrf <name> rd <RD>` | Route Distinguisher for this VRF's VPN NLRI |
| `router bgp vrf <name> label-mode per-vrf` | One MPLS label per VRF (the default) |
| `router bgp vrf <name> neighbor <addr> remote-as <asn>` | A CE peer in the VRF |
| `router bgp vrf <name> afi-safi ipv4 network <prefix>` | Originate a local route into the VRF |

`label-mode` defaults to `per-vrf`: a single label is bound to the
whole VRF, and the egress lookup that follows the label pop happens in
the VRF table. (`per-route` / `per-nexthop` are accepted by the parser
for forward compatibility; the data path allocates one label per VRF
today.)

## Per-VRF label allocation

Each VRF that BGP runs gets one MPLS label, allocated when its per-VRF
task spawns and reclaimed when the VRF is removed. The labels are not
drawn from the raw 20-bit space — they come from a **dynamic label
block** the RIB's label manager reserves for BGP:

* The block lives in a band **above the SR-MPLS ranges** (the default
  SRGB is `16000..23999` and SRLB `15000..15099`). The dynamic pool
  starts at label **100000**, so a per-VRF label can never collide with
  an IS-IS / OSPF prefix-SID or adjacency-SID in the kernel MPLS table.
* BGP requests a block from the RIB at startup. If a VRF is configured
  before the block is granted it spawns label-less and is reconciled —
  given a real label and re-advertised — the moment the block arrives.
* The block **grows on demand**: a fleet larger than the initial block
  triggers a follow-up request, and **shrinks** again — when enough
  VRFs are removed to free a whole block, BGP returns it to the RIB so
  the space is available to other protocols.

The allocated label is stamped onto every VPNv4 / VPNv6 route the VRF
exports (the RFC 4364 label field of the advertised NLRI), so a remote
PE learns which label to push when it forwards traffic toward this VRF.

## Forwarding plane

Two kinds of entry result from an L3VPN PE, and zebra-rs programs both:

**Ingress decap (this PE is the egress for its own label).** For each
VRF, an AF_MPLS route binds the per-VRF label to a pop-and-VRF-lookup
action. A remote PE's VPN packet carrying our label is popped and
routed via the VRF master device, which lands the inner lookup in the
VRF's table:

```
$ ip -f mpls route
...
100000 dev vrf1 proto bgp
```

Here `100000` is `vrf1`'s per-VRF label — drawn from the dynamic block,
sitting cleanly above the IS-IS SR labels (`15000`–`16800`) in the same
table — popped to `dev vrf1`, attributed to `proto bgp`.

**Imported remote-PE routes (this PE is the ingress).** A VPN route
imported into the VRF is installed into the VRF table with a two-label
stack pushed over the resolved transport next-hop: the remote PE's
service label (inner) under the transport label that reaches that PE
(outer). The transport label is found by recursively resolving the
remote PE's next-hop through the IGP — an SR-MPLS prefix-SID in the
example below — so the egress and labels track IGP reconvergence.
CE-learned routes in the same VRF install as plain next-hop entries:

```
$ ip route show table 1
1.2.3.4 nhid 7 via 10.100.0.2 dev enp0s8 proto bgp onlink
9.9.9.9 nhid 15  encap mpls  16800/80 via 192.168.10.2 dev enp0s6 proto bgp onlink
192.168.5.0/24 nhid 15  encap mpls  16800/80 via 192.168.10.2 dev enp0s6 proto bgp onlink
10.100.0.0/24 dev enp0s8 proto kernel scope link src 10.100.0.1
```

* `9.9.9.9` and `192.168.5.0/24` are **imported** VPN routes:
  `encap mpls 16800/80` pushes `16800` (the IS-IS prefix-SID toward the
  egress PE) outermost and `80` (the remote PE's VPN service label)
  innermost, then forwards via the resolved IGP next-hop
  `192.168.10.2 dev enp0s6`.
* `1.2.3.4` is **CE-learned** inside the VRF — a plain next-hop entry,
  no MPLS — installed alongside the imported routes by the per-VRF FIB
  arbitration (whichever path wins best-path in the VRF's Loc-RIB is
  the one programmed).

A route is only advertised and installed once its next-hop resolves, so
an unreachable transport never produces a black-holing FIB entry; when
the transport reroutes, the labelled entry is re-resolved and
re-installed.
