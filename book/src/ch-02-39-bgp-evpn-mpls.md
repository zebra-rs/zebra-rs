# EVPN over MPLS (RFC 7432)

EVPN's L2 services — Type-2 (MAC/IP) and Type-3 (Inclusive Multicast) — over
plain MPLS: the encapsulation RFC 7432 was written for, and the one zebra-rs
supported last. A CE frame is carried under a per-EVI **service label**,
imposed beneath whatever transport LSP reaches the egress PE, which pops it
and bridges the frame into that EVI's bridge domain.

> **This needs the cradle eBPF data plane.** Linux has no action that pops an
> MPLS label and hands the exposed Ethernet frame to a bridge — that gap is
> precisely why EVPN-over-MPLS L2 was unsupported for so long. The control
> plane here programs [cradle](ch-02-00-zebra-integration.md) directly and
> deliberately skips netlink for the decap. VXLAN and SRv6 have kernel data
> paths; this one does not.
>
> EVPN **Type-5** (IP Prefix) is a different story — it is an L3 service and
> rides the ordinary VPNv4/VPNv6 MPLS data path, kernel included. See
> [EVPN Type-5](ch-02-06-bgp-evpn-type5.md).

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
own — classifies traffic exactly as a PE does.

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

## Limitations

- **Requires cradle** (`system cradle grpc-endpoint`). Without it the routes
  are advertised and received but nothing forwards.
- **IPv4 underlay only** in the data plane today; an IPv6-underlay PE punts
  rather than misforwarding.
- **Single-homed.** Multihoming (Type-1/Type-4 and the ESI label's
  split-horizon check) is not implemented for MPLS.
- **No control word.** RFC 7432 leaves it optional and both ends must agree.
  Its absence is only a hazard where a P router hashes deeply enough to
  mistake a customer frame beginning with nibble 4 or 6 for an IP packet.
- **EVPN-VPWS** (RFC 8214) over MPLS is not implemented; VPWS is SRv6-only.
