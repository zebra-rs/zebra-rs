# EVPN over MPLS (RFC 7432)

EVPN's L2 services — Type-2 (MAC/IP) and Type-3 (Inclusive Multicast) — over
plain MPLS: the encapsulation RFC 7432 was written for, and the one zebra-rs
supported last. A CE frame is carried under a per-EVI **service label**,
imposed beneath whatever transport LSP reaches the egress PE, which pops it
and bridges the frame into that EVI's bridge domain.

> **This needs the cradle eBPF data plane.** Linux has no action that pops an
> MPLS label and hands the exposed Ethernet frame to a bridge — that gap is
> precisely why EVPN-over-MPLS L2 was unsupported for so long. The control
> plane here programs [cradle](ch-16-00-ebpf.md) directly and
> deliberately skips netlink for the decap. Of the three encapsulations only
> VXLAN has a kernel L2 data path — [SRv6](ch-02-41-bgp-evpn-srv6.md) is
> engine-only too.
>
> EVPN **Type-5** (IP Prefix) is a different story — it is an L3 service and
> rides the ordinary VPNv4/VPNv6 MPLS data path, kernel included. See
> [EVPN Type-5](ch-02-06-bgp-evpn-type5.md).

The [`playset/bgp-evpn-mpls`](https://github.com/zebra-rs/zebra-rs/tree/main/playset/bgp-evpn-mpls)
lab runs this chapter end to end — two PEs and a pure-transit P router over
an IS-IS SR-MPLS underlay, one stretched segment, fully dynamic.

## Configuration

```
router bgp 65001 {
  global {
    router-id 10.255.0.1;
  }
  neighbor 10.255.0.2 {
    remote-as 65001;
    afi-safi { name evpn; enabled true; }
  }
  afi-safi {
    name evpn;
    advertise-all-vni true;
    encapsulation mpls;
    evi 100 {
      bridge br100;
    }
  }
}
```

### Why the EVI must be declared

Under `encapsulation vxlan` or `srv6`, zebra-rs works out which bridge domains
to advertise by reading the kernel: each bridge's VXLAN slave supplies a VNI,
and that VNI is the service identifier on the wire.

An MPLS EVI has no VNI to read. So it is declared: `evi <id> { bridge <name> }`
names the instance and the bridge whose L2 domain it carries. The id then does
triple duty — it is the bridge domain, the low 24 bits of the auto-derived RD
(`<router-id>:<id>`) and of the route target (`<local-AS>:<id>`) — which keeps
it interchangeable with a VNI everywhere else in the EVPN path.

The **service label is not the EVI id.** It is allocated from the same dynamic
MPLS block the per-VRF L3VPN labels come from, so `evi 100` will advertise some
label like 16 or 100017. That is the number a remote PE imposes; the EVI id is
only the service's name.

## What goes on the wire

| | VXLAN / SRv6 | MPLS |
|---|---|---|
| Type-2 NLRI service field | VNI | **service label** |
| Type-3 PMSI label field | VNI | **BUM service label** |
| Next hop / PMSI tunnel id | local VTEP | **router-id** |
| Encapsulation ext. community | VXLAN (8) | **absent** |

That last row is the encapsulation signal itself: RFC 8365 §5.1.3 makes MPLS
the default and marks it by *omitting* the Encapsulation extended community.
zebra-rs reads a received route the same way (and also accepts an explicit
tunnel type 10), so a route reflector — which has no `encapsulation` of its
own — classifies traffic exactly as a PE does. Flood state is partitioned by
the same classification: an IMET carrying an MPLS BUM label populates only
MPLS replication slots and never enters the VXLAN head-end flood set (an
`End.DT2M`-bearing IMET likewise stays out), so a mixed-encapsulation fabric
cannot deliver a BUM frame twice.

## Forwarding

**Ingress.** A frame from a CE port whose destination MAC resolves to a remote
PE is imposed with `[transport LSP…][service label, S=1]` under an `0x8847`
Ethernet header. The FDB row names only the remote PE; the data plane resolves
the adjacency by a FIB lookup on it, which is also what supplies the transport
labels — so the control plane advertises a *PE*, never a tunnel.

**Egress.** The service label's ILM pops it and bridges the exposed frame in
the EVI's bridge domain, reusing the same hand-off SRv6's `End.DT2U` decap
uses — so split horizon, MAC learning and flooding all behave identically
across the three encapsulations.

**BUM** is ingress-replicated: each remote PE's Type-3 becomes a replication
slot, and a flooded frame gets one copy per slot carrying that PE's BUM label.

### Enabling the data plane

Because none of this forwarding exists in the kernel, the EVI's label, its
decap and every remote MAC are programmed **only** into cradle. Two
separate things have to be true — the control plane will happily advertise
and receive routes with either of them missing:

```
system {
  ebpf {
    enabled true;
  }
}
interface enp0s6 {
  ebpf {
    enabled true;
  }
}
interface enp0s7 {
  ebpf {
    enabled true;
  }
}
```

- **`system ebpf enabled`** supervises the engine as a child process and
  **implies the FIB tee** — the service label, the decap ILM and the EVPN
  FDB are carried across as soon as the managed engine is up. For an
  **externally-run** cradle, `system cradle enabled` activates the tee
  standalone instead (point it with `system cradle grpc-endpoint`; that
  leaf is an endpoint override and enables nothing by itself).
- **`interface <name> ebpf enabled`** attaches a port. Both the core-facing
  port (where labelled frames arrive) and the CE-facing port (where the
  bridge's access traffic arrives) must be attached.

See the [eBPF data plane](ch-16-00-ebpf.md) chapter for the engine's
lifecycle and full command set.

## Verification

```
zebra-rs# show bgp evpn
Route Distinguisher: 10.255.0.1:100
 *>  [3]:[0]:[32]:[10.255.0.1]
                    10.255.0.1                 0         32768 i
                    Extended community: RT:65001:100
                    PMSI: ingress-replication endpoint:10.255.0.1 label:16
```

`label:` rather than `vni:` is the render for a path with no Encapsulation
EC — one PMSI field, two meanings.

```
zebra-rs# show mpls ilm
   P Dist Local  Outgoing    Prefix             Outgoing     Next Hop
          Label  Label       or ID              Interface
-- - ---- ------ ----------- ------------------ ------------ ---------------
*> B 20   16     Pop         EVPN Decap (bd 100 ) -
```

The decap ILM at the service label. There is no outgoing interface because the
pop delivers into a bridge domain rather than out a port — and no kernel LFIB
entry to compare it against, since this one lives only in the data plane.

### Check the data-plane side too

`show mpls ilm` and `show bgp evpn` are the RIB's and BGP's *intent*. Because
there is no kernel LFIB row to cross-check, a correct-looking control plane on
both PEs is not evidence that anything forwards — the frames arrive with the
right service label on top and get dropped. Two commands read the engine
itself and close that gap:

- **`show ebpf mpls`** dumps the engine's incoming-label map. Every label
  `show mpls ilm` lists must appear here. A service label present in
  `show mpls ilm` and absent from `show ebpf mpls` means the tee never
  carried it — check `show ebpf` for `FIB tee: enabled`.
- **`show ebpf l2`** dumps the L2 FDB: MACs learned from remote Type-2
  routes alongside the ones the data plane learned locally on the CE ports.

An empty table prints nothing at all, which for this service is itself the
diagnosis rather than a quiet success.

> The state is **replayed** on reconnect: when the tee comes up — or comes
> back after an engine restart — the routes, ILMs and EVPN state are
> re-programmed from the RIB with no operator action. This matters at
> startup in particular, since a PE allocates its EVI label and programs the
> decap during config load, which is typically while the tee is still
> connecting.

## IPv6 PEs

Nothing in RFC 7432 requires an IPv4 core — MPLS imposes no outer IP
header, so the PE's address family lives only in the control plane and the
adjacency. Three pieces make an IPv6-only deployment:

* **`vtep-source`** names the v6 loopback the EVPN routes advertise. The
  router-id — the default source for an MPLS PE's next hop and IMET
  Originating Router IP — can only express IPv4, so a v6 PE sets it
  explicitly (the leaf is shared with VXLAN, where it covers deviceless
  services; here it covers every origination):

  ```
  afi-safi {
    name evpn;
    encapsulation mpls;
    vtep-source 2001:db8:255::1;
    ...
  }
  ```

* **A labeled route to the far PE's v6 loopback** supplies the transport
  LSP. IS-IS SR-MPLS prefix-SIDs are IPv4-only today, so on a v6 core the
  static form carries the stack — the `label` list on an ipv6 route
  nexthop, the exact sibling of the ipv4 one:

  ```
  router static ipv6 route 2001:db8:255::2/128 {
    nexthop 2001:db8:12::2 {
      label 100;
    }
  }
  ```

  The datapath resolves a remote MAC's service-label imposition by a FIB6
  /128 lookup on the PE, picking up this route's transport labels — the
  same nexthop-0 shape as the IPv4 core.

* **Static label bindings with v6 nexthops** give a pure-transit P router
  its pops. The explicit `interface` leaf opts each binding onto the eBPF
  XDP fast path — the operator's assertion of a core-facing hop, needed
  because the P holds no route for the exposed payload (the PEs'
  loopbacks) and the XDP redirect delivers only between XDP-attached
  ports. A binding without it keeps the FIB-assisted pop, which reaches
  any device but needs a route for what the pop exposes:

  ```
  router static mpls label 100 {
    nexthop 2001:db8:23::2 {
      interface p-pe2;
    }
  }
  ```

The
[`playset/bgp-evpn-mpls6`](https://github.com/zebra-rs/zebra-rs/tree/main/playset/bgp-evpn-mpls6)
lab is the IPv6 twin of this chapter's — the same stretched segment and
pure-transit P, with static labels replacing the IGP and even the PEs' own
iBGP session riding the LSP through the routeless P. Its E-Line sibling is
[`playset/bgp-evpn-vpws-mpls6`](https://github.com/zebra-rs/zebra-rs/tree/main/playset/bgp-evpn-vpws-mpls6).

## Limitations

- **Requires cradle** (`system ebpf enabled` for the managed engine, or
  `system cradle enabled` teeing to an external one — see
  [Enabling the data plane](#enabling-the-data-plane)). Without it the routes
  are advertised and received but nothing forwards.
- **Single-homed.** Multihoming (Type-1/Type-4 and the ESI label's
  split-horizon check) is not implemented for MPLS.
- **No control word.** RFC 7432 leaves it optional and both ends must agree.
  Its absence is only a hazard where a P router hashes deeply enough to
  mistake a customer frame beginning with nibble 4 or 6 for an IP packet.
- **EVPN-VPWS** (RFC 8214) over MPLS is implemented — a per-service label
  in the Type-1 and a pop-to-AC disposition; see
  [EVPN VPWS](ch-02-38-bgp-evpn-vpws.md).
