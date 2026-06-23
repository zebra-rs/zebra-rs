# BGP EVPN IGMP/MLD Proxy (RFC 9251)

zebra-rs implements the **EVPN IGMP/MLD Proxy** procedures of RFC 9251,
which add *selective* multicast delivery to an EVPN. Without it, an
ingress PE floods every BUM (broadcast / unknown-unicast / multicast)
frame to **all** remote VTEPs over the Type-3 (Inclusive Multicast)
tree. With it, a PE learns which groups its locally-attached hosts have
joined (via the kernel bridge's IGMP/MLD snooping) and advertises that
interest in BGP (a **Type-6 SMET** route), so other PEs can constrain
multicast to the groups that were actually asked for. Both the control
plane (snoop → SMET → import) and the per-VTEP data plane — a kernel
**VXLAN MDB** entry that replicates the group only to the VTEP that
asked for it, instead of head-end-replicating to every PE — are
implemented and validated.

Three new EVPN route types and one extended community carry this:

| Object | Role |
| ------ | ---- |
| **Type-6** Selective Multicast Ethernet Tag (SMET) | "a host behind me wants `(*,G)`/`(S,G)`" — the per-group interest advertisement |
| **Type-7 / Type-8** Multicast Join / Leave Synch | synchronize membership across PEs on a multihomed Ethernet Segment |
| **Multicast Flags** Extended Community | rides the Type-3 IMET route to advertise IGMP/MLD proxy *capability* |

zebra-rs implements **Type-6 (SMET)** and the **Multicast Flags EC** for
single-homed PEs. Type-7 / Type-8 (all-active multihoming synch) are not
implemented — they depend on Ethernet-Segment / DF-election support.

## How it works

The Linux kernel bridge does the IGMP/MLD snooping; zebra-rs bridges
that state to and from BGP — it does not run its own IGMP/MLD engine.

**Origination (egress / receiver PE).** When a host joins a group, the
snooping bridge programs a kernel MDB entry and emits an `RTM_NEWMDB`
netlink notification. zebra-rs maps the bridge to its VXLAN VNI and
originates a **Type-6 SMET** route: RD `<router-id>:<VNI>`, route-target
the per-VNI EVI RT `<AS>:<VNI>`, next hop the local VTEP, and a Flags
octet encoding the IGMP/MLD version and include/exclude mode. A leave
withdraws it. Existing memberships at start-up are picked up by an
`RTM_GETMDB` dump.

**Reception (ingress / source PE).** A received SMET whose RT matches a
local VNI is programmed as **two** kernel MDB entries:

* a **bridge MDB** entry — `bridge mdb add dev <bridge> port <vxlan>
  grp G [src S]` — that registers the group on the VXLAN bridge port so
  the snooping bridge forwards it *into* the overlay rather than dropping
  it; and
* a **VXLAN MDB** entry on the VXLAN device itself — `bridge mdb add dev
  <vxlan> grp G [src S] src_vni <VNI> dst <VTEP>` — carrying the
  originating PE as `dst`, so the kernel replicates the group **only** to
  the VTEP that asked for it instead of head-end-replicating it to every
  VTEP on the Type-3 BUM tree.

The per-VTEP `dst` requires a VNI-aware VXLAN, so zebra-rs creates its
EVPN VXLAN devices in the kernel's **`external vnifilter`** model
(equivalent to `ip link add … type vxlan external vnifilter`, with each
VNI registered via `bridge vni add`); FDB and MDB entries are keyed by
`src_vni`. Unregistered groups still flood over the Type-3 tree, so a
non-proxy PE (which never sends SMET) keeps receiving them — no explicit
flood-vs-selective reconciliation is needed.

**Capability signalling.** A proxy-capable PE attaches the **Multicast
Flags Extended Community** to its Type-3 IMET route so peers know it
performs proxying.

## Configuration

The feature is opt-in per speaker under the `evpn` address family, and
builds on [`advertise-all-vni`](ch-00-03-vxlan-configuration.md) (which
makes local VXLAN VNIs participate in EVPN):

```
set router bgp afi-safi evpn advertise-all-vni true
set router bgp afi-safi evpn igmp-mld-proxy true
```

* `igmp-mld-proxy true` attaches the Multicast Flags EC (both the IGMP
  and MLD proxy bits) to originated Type-3 IMET routes, and enables
  Type-6 SMET origination from locally-snooped membership. Defaults to
  `false`. Per-protocol granularity (IGMP-only / MLD-only) is a
  follow-up.

The VXLAN device must sit in an **IGMP-snooping bridge** for membership
to be learned and for selective entries to be programmed:

```
ip link add br10 type bridge mcast_snooping 1
ip link set vxlan10 master br10
ip link set br10 up
```

A neighbor must negotiate the L2VPN/EVPN address family:

```
set router bgp neighbor 192.168.0.1 remote-as 65001
set router bgp neighbor 192.168.0.1 afi-safi evpn enabled true
```

## Verification

Received and originated SMET routes appear in `show bgp evpn`, rendered
as `[6]:[EthTag]:[SrcLen]:[Src]:[GrpLen]:[Grp]:[OrigLen]:[Orig]`
(a `(*,G)` route shows the source as `[0]:[*]`). The Multicast Flags EC
renders as `mcast-flags:` followed by `I` (IGMP) / `M` (MLD):

```
show bgp evpn
...
Route Distinguisher: 192.168.0.2:10
 *>  [6]:[0]:[0]:[*]:[32]:[239.1.1.1]:[32]:[192.168.0.2]
                    192.168.0.2 ...
                    RT:65001:10 ET:8
 *>  [3]:[0]:[32]:[192.168.0.2]
                    RT:65001:10 ET:8 mcast-flags:IM
```

Filter by route type with `show bgp evpn route-type smet`.

The registered group is visible in both MDBs on the ingress PE (it has
no local member, so the entries can only come from the received SMET).
The bridge MDB registers the VXLAN port; the VXLAN MDB carries the
per-VTEP `dst`:

```
bridge mdb show dev br10
dev br10 port vxlan10 grp 239.1.1.1 permanent

bridge mdb show dev vxlan10
dev vxlan10 port vxlan10 grp 239.1.1.1 permanent dst 192.168.0.2 src_vni 10
```

## Limitations

* **Single-homed only** — Type-7 / Type-8 multihoming synch routes are
  not implemented.
* The SMET **Flags** octet is derived per address family (IPv4 →
  IGMPv3, IPv6 → MLDv2; exclude mode for `(*,G)`, include for `(S,G)`)
  rather than from the kernel MDB group-mode.
* Selective entries are programmed with bridge **VLAN 0** (non
  VLAN-aware bridge); per-VLAN mapping is a follow-up.
* The Multicast Flags EC capability gate (skip selective replication
  toward non-proxy PEs) is an optimization that is not yet applied —
  correctness still holds because the kernel floods unregistered groups.
