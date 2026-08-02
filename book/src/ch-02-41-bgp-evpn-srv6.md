# EVPN over SRv6 (RFC 9252)

EVPN's L2 services — Type-2 (MAC/IP) and Type-3 (Inclusive Multicast) — over
an SRv6 data plane: a CE frame is carried **MAC-in-SRv6** toward the egress
PE's L2 Service SID, a per-VNI **End.DT2U** for known unicast and an
**End.DT2M** for BUM, both carved dynamically from the PE's locator and
advertised in the routes' SRv6 L2 Services attribute (RFC 9252 §6).

> **This needs the cradle eBPF data plane.** Linux has no `End.DT2U` or
> `End.DT2M` seg6local action — of the three EVPN encapsulations, only
> VXLAN has a kernel L2 data path. The control plane programs
> [cradle](ch-16-00-ebpf.md) directly and deliberately skips netlink for
> these SIDs.
>
> EVPN **Type-5** (IP Prefix) is an L3 service and uses the ordinary
> `End.DT46` L3VPN machinery instead — see
> [EVPN Type-5](ch-02-06-bgp-evpn-type5.md).

The [`playset/bgp-evpn-srv6`](https://github.com/zebra-rs/zebra-rs/tree/main/playset/bgp-evpn-srv6)
lab runs this chapter end to end — two PEs over an IS-IS SRv6 underlay,
one stretched segment, everything below captured from it.

## Configuration

```
system {
  ebpf {
    enabled true;
  }
}
segment-routing {
  locator LOC1 {
    prefix fcbb:bbbb:1::/48;
    behavior usid;
  }
}
router bgp 65001 {
  global {
    router-id 10.0.0.1;
  }
  segment-routing {
    srv6 { locator LOC1; }
  }
  neighbor 2001:db8::2 {
    remote-as 65001;
    update-source 2001:db8::1;
    afi-safi { name evpn; enabled true; }
  }
  afi-safi {
    name evpn;
    advertise-all-vni true;
    encapsulation srv6;
  }
}
```

### The VNI declaration

Unlike [MPLS](ch-02-40-bgp-evpn-mpls.md) — where the instance is declared
with an `evi` list because there is no VNI to read — the SRv6 encapsulation
keeps VXLAN's model: zebra-rs reads the kernel, and each bridge's VXLAN
slave supplies the VNI that names the instance (the RD `<router-id>:<vni>`
and RT `<AS>:<vni>` derive from it). So a `vxlan100` device enslaved to
`br100` *declares* VNI 100; with `encapsulation srv6` the kernel VXLAN path
stays inert and the device is only the declaration.

The **SIDs are not configured.** `encapsulation srv6` swaps the service
binding the routes carry: a per-VNI `End.DT2U` on every Type-2 and an
`End.DT2M` on the Type-3, allocated from the BGP SRv6 locator on demand.

## What goes on the wire

| | VXLAN | SRv6 | MPLS |
|---|---|---|---|
| Type-2 service binding | VNI (NLRI label field) | **End.DT2U SID** (SRv6 L2 Services attribute) | service label (NLRI label field) |
| Type-3 BUM binding | VNI (PMSI) | **End.DT2M SID** (SRv6 L2 Services attribute) | BUM service label (PMSI) |
| Next hop | local VTEP | **local VTEP address** | router-id |

A receiver classifies by the SID's presence — the SRv6 L2 Services
attribute wins before any Encapsulation-EC reasoning — so SRv6, VXLAN and
MPLS PEs can coexist under one route reflector. Flood state is partitioned
the same way: an IMET carrying an `End.DT2M` SID populates only SRv6
replication slots and never enters the VXLAN head-end flood set (an MPLS
BUM-label IMET likewise stays out), so a mixed-encapsulation fabric cannot
deliver a BUM frame twice.

## Forwarding

**Ingress.** A frame from a CE port whose destination MAC resolves to a
remote PE is encapsulated in an outer IPv6 header (next-header 143,
*Ethernet*) addressed to that PE's `End.DT2U` SID. The FDB row names only
the SID; the data plane resolves the underlay adjacency by a FIB lookup on
it — the locator route the IGP installed.

**Egress.** The `End.DT2U` decap strips the outer header and bridges the
inner frame in the SID's bridge domain — the same hand-off MPLS's `pop-l2`
ILM and VXLAN's decap use, so split horizon, MAC learning and flooding
behave identically across the three encapsulations.

**BUM** is ingress-replicated: each remote PE's Type-3 becomes a
replication slot, and a flooded frame gets one copy per slot addressed to
that PE's `End.DT2M` SID.

Enabling the data plane is the same three-knob story as MPLS — see
[Enabling the data plane](ch-02-40-bgp-evpn-mpls.md#enabling-the-data-plane)
(`system ebpf enabled` supervises the engine and implies the tee; each
core- and CE-facing port needs `interface <name> ebpf enabled`).

## Verification

Everything is dynamic: the engine learns CE MACs in XDP and streams them
to zebra-rs over WatchFdb, each becoming a Type-2 carrying this PE's
`End.DT2U` SID:

```
pe1>show bgp evpn
Route Distinguisher: 10.0.0.1:100
 *>  [2]:[0]:[48]:[ce:c5:b5:8f:b5:e4]
                    2001:db8::1                0         32768 i
                    Local SID: fcbb:bbbb:1:41:: (End.DT2U)
                    Extended community: RT:65001:100 ET:8
 *>  [3]:[0]:[128]:[2001:db8::1]
                    2001:db8::1                0         32768 i
                    Local SID: fcbb:bbbb:1:40:: (End.DT2M)
                    Extended community: RT:65001:100 ET:8
                    PMSI: ingress-replication endpoint:2001:db8::1 vni:100
Route Distinguisher: 10.0.0.2:100
 *>  [2]:[0]:[48]:[ca:c4:f0:78:ef:a5]
                    2001:db8::2                0    100      0 i
                    Remote SID: fcbb:bbbb:2:41:: (End.DT2U)
                    Extended community: RT:65001:100 ET:8
```

The engine's FDB shows the split — locally-learned MACs with an age,
remote MACs bound to the peer's service SID:

```
pe1>show ebpf l2
mac                 vlan      oif flags       age_ms remote_sid
ce:c5:b5:8f:b5:e4    100        2 learned       4418
ca:c4:f0:78:ef:a5    100        0 remote           0 fcbb:bbbb:2:41::
```

And the counters carry the story — BUM flooded over the `End.DT2M`
tunnel, unicast MAC-in-SRv6 encapsulated, everything decapped on the way
in:

```
pe1>show ebpf stats
l2_forward     5
l2_flood       12
srv6_l2_encap  1
srv6_l2_decap  13
srv6_l2_bum    12
```

As with MPLS, `show bgp evpn` is intent — `show ebpf l2` and
`show ebpf stats` read the engine itself, and the teed state is replayed
automatically when the engine restarts.

## Limitations

- **Requires cradle** — without an engine the routes are advertised and
  received but nothing forwards (the kernel has no DT2U/DT2M action).
- **Multihoming is signalled in full** (Type-1/Type-4, DF election, the
  ESI on Type-2s); what remains open across all encapsulations is the
  aliasing / mass-withdraw *consumer* side for E-LAN MACs, and ARP
  suppression.
- **EVPN-VPWS** (RFC 8214) over SRv6 — the point-to-point E-Line with
  `End.DX2`/`End.DX2V` — is covered in
  [EVPN VPWS](ch-02-38-bgp-evpn-vpws.md).
