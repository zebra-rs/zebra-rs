# EVPN multihoming with a hardware-offloaded Open vSwitch dataplane (OVN)

## Status (2026-10-10): proposal for review, not accepted

*Request for comments; no code depends on it. Follows
[`bgp-evpn-multihoming-dataplane.md`](bgp-evpn-multihoming-dataplane.md)
and the kernel integration in #2477, #2488 and #2502.*

---

## 0. Summary

[`bgp-evpn-multihoming-dataplane.md`](bgp-evpn-multihoming-dataplane.md) concludes
that the kernel VXLAN backend stays single-homed. The Linux bridge has no
dataplane for the non-DF and split-horizon filters, and zebra-rs will not add
the tc/eBPF workarounds that would fake them. A multihomed Ethernet Segment
therefore requires `system ebpf enabled` (cradle).

That conclusion is about the **Linux bridge forwarding frames**. When zebra-rs
is the routing daemon for OVN, the bridge does not forward: Open vSwitch does.
The bridge, VXLAN and VRF devices only carry state between zebra-rs and
ovn-controller. As a result, the obstacle the earlier document identifies does
not apply to OVN:

- **Forwarding toward a segment on other PEs** (aliasing, mass withdraw,
  single-active receive side) needs only **zebra-rs** work. OVN already turns
  kernel FDB entries backed by nexthop groups into weighted OpenFlow select
  groups. zebra-rs's kernel backend does not create those groups yet. The work
  uses native kernel objects, not workarounds, and the lab can validate it
  today.
- **OVN chassis acting as PEs on a segment** (the non-DF and split-horizon
  filters, single-active blocking, fast failover) is straightforward in OVS,
  which sees the ingress VTEP and the lookup result in one pipeline. It needs an
  **ovn-controller patch** and an agreed way for zebra-rs to hand OVN the DF role
  and the segment's peer VTEPs. That interface is the main decision this document
  asks for.

- **Hardware offload (HWOL)** of the OVS datapath does not change the
  zebra-rs side, but it decides which of these paths stay in hardware (§6).
  Part B's filters are plain matches and drops, and offload. Part A does not
  today: OVN load-balances a multihomed MAC with a `dp_hash` select group, and
  OVS's tc offload has no handler for the datapath `hash` action. That traffic
  stays in the software datapath. The fix belongs in OVN or OVS; the review
  needs to know about it before part A is sold as an HWOL feature.

**Proposal:** do part A in zebra-rs now. Settle the part B interface and its use
case with the maintainer (and with OVN upstream) before writing code.

---

## 1. How zebra-rs and OVN share state today

OVN's native EVPN support (ovn-controller, `controller/neighbor*.c`,
`evpn-*.c`) uses the kernel as its interface to the routing daemon. Per VNI,
the operator creates a Linux bridge and VXLAN device. zebra-rs adopts them
(#2477) and OVS carries the traffic over its own EVPN tunnel ports.

| Direction | Kernel object | Written by | Read by |
|---|---|---|---|
| Remote VTEPs (Type-3) | zero-MAC FDB entry on the VXLAN device | zebra-rs | ovn-controller (`evpn-binding.c`) → one EVPN binding per (VTEP, VNI) |
| Remote MACs (Type-2) | FDB entry on the VXLAN device: a VTEP (`NDA_DST`) **or a nexthop group (`NDA_NH_ID`)** | zebra-rs | ovn-controller (`evpn-fdb.c`) → OpenFlow, select groups for `NDA_NH_ID` |
| Remote IPs (Type-2) | `NOARP` `extern_learn` neighbors on the bridge | zebra-rs | ovn-controller (`evpn-arp.c`) → ARP/ND suppression |
| Local MACs/IPs to advertise | static FDB/neighbor entries on a per-VNI "advertise" interface (`dynamic-routing-advertise-ifname`) | ovn-controller | zebra-rs → Type-2 origination |
| Type-5 / VRF routes | VRF routing table | both | both |

The `adapter` principle in the lab is "Linux kernel netlink; no OVN-specific
API". zebra-rs has no OVN code; OVN has no zebra-rs code.

Two OVN facts matter below:

1. OVN NEWS (dynamic routing): *"Add ECMP/multi-homing support for EVPN FDB
   entries. FDB entries backed by a kernel nexthop group are load-balanced via
   OpenFlow select groups with weighted buckets."* (`controller/evpn-fdb.c`).
2. EVPN ingress resolves the remote VTEP up front. `physical_consider_evpn_binding`
   (`controller/physical.c`) matches the tunnel port, VNI, `tun_src` and `tun_dst`,
   and loads that VTEP's binding key into `MFF_LOG_INPORT`. In OVN's logical
   pipeline, the source VTEP of an overlay frame is simply its logical input port.

---

## 2. Why the kernel limitation does not carry over

The earlier document (§2) traces every kernel problem to the netdev boundary.
The kernel's L2 path is a chain of separate devices (vxlan, then bridge, then
bond), and the two facts the filters need are produced early and gone by the
egress decision:

- the **source VTEP**, known at VXLAN decap;
- whether the frame is **BUM, including unknown unicast**, known at the FDB lookup.

OVS, like cradle, is one pipeline. Fact 2 above makes the source VTEP the
logical input port, available at egress. OVN's L2 lookup knows when a
destination MAC is unknown, and registers carry both facts to the output
decision. C4 and C5 of the earlier document's inventory become matches on the
egress side of the segment's port, with no metadata smuggling.

| # | Challenge (from the earlier document, §3) | Kernel bridge | OVS / OVN |
|---|---|---|---|
| C4 | non-DF filter | no primitive (tc + `l2_miss`, 6.5) | egress match: from overlay ∧ BUM ∧ ¬DF(ES, VNI) → drop |
| C5 | split horizon (local bias, RFC 8365 §8.3.1) | not representable | egress match: inport ∈ peer bindings(ES) ∧ BUM → drop |
| C6/C7 | aliasing, mass withdraw | FDB nexthop groups (5.9) | **already consumed** from the kernel groups |
| C8 | fast local failover | `backup_port` + `backup_nhid` (6.5) | OpenFlow fast-failover / select group to the peers |
| C9 | single-active | partly | egress and ingress drop on the standby port; receive side = group holding only the forwarder |
| C14 | per-reason drop counters | tc counters | flow statistics per drop flow |

---

## 3. Two problems, not one

**A. OVN forwards toward a segment hosted elsewhere.** This is the lab today:
cEOS leaves with all-active LACP bonds to the hosts. OVN chassis are ingress PEs
for those segments and need aliasing (C6), mass withdraw (C7) and, for
single-active segments, the forwarder only (C9 receive side).

**B. OVN chassis are themselves PEs on a segment.** Something physical is LAG'd
to two or more chassis: a bare-metal server, an appliance, or a provider network
reached through a localnet port on several gateway chassis. These need all of
C1–C5, C8, C9 and C11. VMs attach to one hypervisor, so this matters only for
physical attachments, and the use case should be confirmed first (§8, question 1).

---

## 4. Part A: kernel FDB nexthop groups in zebra-rs

### 4.1 What exists

- BGP computes the segment groups from per-ES and per-EVI Ethernet A-D routes:
  members are PEs whose per-EVI A-D route is selected and whose per-ES A-D route
  (the liveness signal) is up (`Bgp::evpn_es_nhg_sync`). It sends them to the
  RIB as `SetEsNhg`.
- The RIB records which (ESI, VNI) pairs have a group (`es_groups`) and passes it
  **only to cradle** (`cradle_es_nhg`, `cradle_fdb_es`). On the kernel path,
  `mac_add` installs the first destination and logs the ESI
  (`fib/netlink/handle.rs`, "ESI type … for MAC").
- The support matrix records this as "Kernel backend: first destination only".

### 4.2 Change

On the kernel backend, for each (ESI, VNI) group:

1. One **FDB nexthop per remote VTEP**, shared across groups
   (`RTM_NEWNEXTHOP` with `NHA_FDB`, IPv4 or IPv6 gateway).
2. One **FDB nexthop group per (ESI, VNI)** (`NHA_GROUP` + `NHA_FDB`), replaced
   in place when membership changes.
3. A remote MAC with that ESI is installed on the VXLAN device with
   `NDA_NH_ID = group` (self entry) instead of `NDA_DST`. The bridge master entry
   still points at the VXLAN port.
4. **Mass withdraw:** a per-ES A-D withdrawal changes group membership. That is
   one `RTM_NEWNEXTHOP` replace, and every MAC on the segment follows it.
5. **Single-active:** the group holds only the elected forwarder (cradle's
   slot 0). A change of forwarder is a group replace.
6. **Ordering:** create nexthops, then the group, then FDB entries. Remove in
   reverse. An empty group is replaced by direct `NDA_DST` installs (or removal)
   before the group is deleted.
7. **Recovery:** nexthop IDs are allocated from a zebra-rs-owned range, and
   startup leftovers are swept as for routes (`--leftover-sweep-time`).

Verified on this host (kernel 7.0, iproute2 6.1):

```text
ip nexthop add id 1 via 198.51.100.2 fdb
ip nexthop add id 2 via 198.51.100.3 fdb
ip nexthop add id 100 group 1/2 fdb
bridge fdb add 02:00:00:00:00:01 dev vx0 nhid 100 self   # → "nhid 100 self permanent"
ip nexthop replace id 100 group 1 fdb                    # mass withdraw in one update
ip nexthop add id 3 via 2001:db8::3 fdb                  # IPv6 VTEP
```

### 4.3 Scope and risk

- Contained to the RIB and FIB. BGP already produces the groups, and OVN already
  consumes them.
- It also gives the **plain Linux-bridge backend** aliasing and mass withdraw.
  The bridge forwards known unicast through FDB nexthop groups natively.
- **Single VXLAN device (SVD, `external` + `vnifilter`):** whether an FDB entry
  with `NDA_NH_ID` carries the VNI correctly needs checking. FRR uses the same
  combination, so it is expected to work.
- **Lab validation:** the clab's cEOS bonds are all-active segments. Expected
  results:
  - OVN shows select groups with two buckets per remote MAC;
  - traffic from OVN hosts spreads across both leaves;
  - taking a host's leaf link down shrinks the group in one update, with no
    per-MAC churn.

  This becomes new checks in `test.py`.

---

## 5. Part B: OVN chassis as segment PEs

### 5.1 Division of work

| # | Function | Owner | Mechanism |
|---|---|---|---|
| C1 | segment ↔ port, redundancy mode | zebra-rs config + OVN config | zebra-rs `ethernet-segment <name> interface <port>`. OVN marks which logical/physical port is on the segment. |
| C11 | ESI on local MAC/IP routes | OVN → zebra-rs | OVN writes MACs learned on a segment port to a **per-segment kernel port** instead of the per-VNI advertise interface. zebra-rs's existing attribution (ESI from the port a MAC was learned on, `Bgp::macip_esi`) stamps the ESI with no new code. |
| C3 | DF election | zebra-rs | Already implemented: modulus, HRW, preference, AC-DF, startup delay. |
| C4 | non-DF filter | ovn-controller | egress flow on the segment port per VNI: from overlay ∧ BUM ∧ ¬DF → drop |
| C5 | split horizon | ovn-controller | egress flow: inport ∈ {bindings of peer VTEPs on this segment} ∧ BUM → drop |
| C9 | single-active standby | ovn-controller | drop both directions on the segment port |
| C8 | fast local failover | ovn-controller | segment port down → known unicast for its MACs goes to the peer group |
| C2 | LAG toward the CE | OVS | OVS bonds with a shared `lacp-system-id` across chassis |
| C13 | ARP/ND sync between peers | zebra-rs | Type-2 routes with the ESI (existing control plane) |

### 5.2 The interface: how zebra-rs gives OVN the DF role and peer set

ovn-controller needs two things per segment, keyed by VNI where relevant:
whether this chassis is DF, and which remote VTEPs are peers on the segment.
Both change at runtime: DF re-election, peers joining and leaving.

**Option 1: encode them in kernel state OVN already watches.** This keeps
zebra-rs OVN-agnostic.

- **DF role:** the per-segment port's flood flags in that VNI's bridge
  (`IFLA_BRPORT_FLOOD`, `_MCAST_FLOOD`, `_BCAST_FLOOD` off when non-DF).
- **Peer set:** an FDB nexthop group of the peer VTEPs, attached to the port as
  its `IFLA_BRPORT_BACKUP_PORT` (the VXLAN device) and `IFLA_BRPORT_BACKUP_NHID`
  (6.5). This is exactly the kernel's own fast-failover primitive (C8). OVN reads
  the same object as the split-horizon peer set (C5) and as its failover target.
- **Single-active standby:** to be decided. Candidates are protodown with a
  reason, or the bridge port `locked` flag.

Pros:
- extends the existing contract;
- every object has native kernel semantics, and the backup nexthop is also
  correct for the Linux-bridge backend;
- no new dependency in zebra-rs.

Cons:
- The flood flags are **lossy**: they block BUM from every source, while the
  non-DF filter blocks only BUM from the overlay. OVN would read them as a
  signal and apply the narrower rule. A Linux-bridge dataplane would be stricter
  than RFC 7432 (local BUM would not reach the segment port on a non-DF PE).
- Several objects must change together on re-election. There is no atomic
  update across them (C12), so ovn-controller must tolerate brief
  inconsistency.
- `backup_nhid` needs kernel 6.5, and iproute2 6.5 to inspect by hand.

**Option 2: an explicit OVSDB channel.** zebra-rs writes the roles and peer sets
into the local OVSDB, either `Interface:external_ids` on the segment port or a
dedicated table, and ovn-controller reads them as it reads
`ovn-evpn-local-ip` today.

Pros:
- exact semantics;
- transactional, so a re-election is one transaction;
- easy to extend (counters, provenance) and to inspect with `ovs-vsctl`.

Cons:
- zebra-rs gains an OVSDB client and an OVN-specific interface, against the
  adapter principle;
- OVN upstream has to accept a schema for it.

**Leaning:** option 1. It continues the interface that already works, and its
pieces are useful without OVN. Option 2 is the fallback if the lossy flood-flag
encoding proves unacceptable in review. This is the main question for the
maintainer (§8).

### 5.3 OVN side

This needs an upstream OVN patch, tracked in the OVN tree like the earlier
protocol-filter item:

- configuration marking a port as a segment member (logical switch port option,
  or per chassis);
- monitoring the per-segment kernel port: flood flags, backup nexthop group,
  standby signal;
- writing local MACs learned on the port to that kernel port (C11);
- egress filters (C4, C5), single-active blocking (C9), failover group (C8),
  with flow statistics as drop counters (C14).

---

## 6. Hardware offload

With `other_config:hw-offload=true`, ovs-vswitchd offloads each datapath flow
to tc flower (and from there to a switchdev NIC), or to rte_flow under DPDK. A
flow is offloaded only if every match field and action has a translation. If
any action has none, the flow is refused (`EOPNOTSUPP`) and runs in the
software datapath. zebra-rs only writes kernel state, so offload changes
nothing on its side. It decides whether the forwarding this design enables
runs in hardware. The findings below come from reading OVS `main` (466ceb4)
and OVN `main` (d58221fd8). None of them has been measured on hardware.

### 6.1 Part A: aliasing does not offload today

- OVN programs an FDB entry with more than one path as
  `type=select,selection_method=dp_hash` (`physical_consider_evpn_fdb`,
  `controller/physical.c`).
- OVS translates a `dp_hash` select group into the datapath actions
  `hash` + `recirc`, and picks the bucket in a second pass
  (`pick_dp_hash_select_group`, `ofproto/ofproto-dpif-xlate.c`).
- The tc offload provider (`lib/dpif-offload-tc-netdev.c`) handles `output`,
  VLAN/MPLS push and pop, `set`, `ct`, `recirc`, `drop`, `meter` and
  `check_pkt_len`, but not `hash`. It rejects the whole flow. The DPDK provider
  handles neither `hash` nor `recirc`.

So on an HWOL chassis, known-unicast traffic to a MAC behind a remote
multihomed segment, the bulk of the traffic aliasing exists for, runs in
software. Single-path FDB entries are not affected. The ways out are all
outside zebra-rs:

| Option | Where | Trade-off |
|---|---|---|
| `selection_method=hash` with explicit fields | OVN | ovs-vswitchd hashes at translation time, so the flows offload. But each datapath flow must match the hashed fields exactly, and the flow count grows with the number of L4 flows. |
| Offload `hash` + `recirc` | OVS + kernel + NIC | Best result. Needs a tc representation of the hash action and NIC support. We did not find one in the tc offload code. |
| Pick one path per MAC on HWOL chassis | OVN | Offloads. Gives up load balancing, but keeps fast mass withdraw, because the select group shrinks as paths go. |

Mass withdraw itself is unaffected. When zebra-rs replaces a nexthop group's
members, ovn-controller rewrites one OpenFlow group, and OVS revalidates the
flows that use it. On an HWOL chassis that re-offloads every affected flow,
so convergence scales with the number of offloaded flows behind the segment.
It is still one control-plane update per segment, not per MAC.

### 6.2 Part B: the filters are offload-friendly

- **Split horizon (C5)** turns into a match on the outer source address. OVN
  derives the logical input port from `tun_src`, and tc flower matches it
  (`TCA_FLOWER_KEY_ENC_IPV4_SRC` / `_IPV6_SRC`).
- **The non-DF filter (C4)** and **single-active blocking (C9)** are drops on
  flows that are already offloaded.
- **BUM replication** to several VTEPs is a list of tunnel outputs. Every NIC
  supports this up to a limit on actions per flow. Above that limit, the flood
  flow runs in software. This is not specific to multihoming.

### 6.3 Fast failover (C8)

The kernel's `backup_nhid` acts in the forwarding path: once the port loses
carrier, the next frame goes to the backup group. OVS fast-failover groups
check `watch_port` liveness when a flow is translated, not when a frame is
forwarded. With HWOL, a segment port going down is handled only after the
revalidators re-translate and re-offload the affected flows. Failover time
then depends on the revalidator and on the tc offload rate. It needs
measuring before C8 is claimed as fast on HWOL.

### 6.4 Validation

The containerlab OVN lab has no switchdev NIC. With
`other_config:tc-policy=skip_hw`, OVS still sends every offloadable flow to tc
flower in software. That shows which flows are offloadable
(`ovs-appctl dpctl/dump-flows type=offloaded` against `type=ovs`), but not
NIC limits or timings. Timings need a switchdev NIC (for example a ConnectX or
BlueField in switchdev mode). That is outside what this project can test
today.

---

## 7. Proposed sequence

1. **zebra-rs, part A:** kernel FDB nexthop groups for remote segments, covering
   aliasing, mass withdraw and the single-active forwarder. Add unit tests, a
   Linux namespace scenario (two remote VTEPs advertising the same ESI) and clab
   checks against the cEOS segments. Record which flows offload under
   `tc-policy=skip_hw` (§6.4). Update the support matrix row.
2. **Review:** settle the part B use case and interface (§5.2), and raise the
   OVN-side design upstream.
3. **zebra-rs, part B:** per-segment kernel port attribution (likely config and
   docs only), the DF and peer-set encoding chosen in step 2, and the standby
   signal.
4. **OVN, part B:** filters, failover, counters. Lab: a host LAG'd to two OVN
   chassis.
5. Update `bgp-evpn-multihoming-dataplane.md` §0: "requires `system ebpf
   enabled`" holds when the Linux bridge forwards, not when OVS does.

---

## 8. Questions for review

1. **Use case for part B.** Is "OVN chassis as segment PEs" wanted, and what is
   the segment port: a localnet port on gateway chassis, an L2 gateway port, or
   something else? Part A stands on its own either way.
2. **Interface (§5.2).** Is extending the kernel contract (option 1) acceptable
   given the lossy flood-flag encoding? Or is an explicit channel (option 2)
   preferred despite the OVN-specific dependency?
3. **Part A on the plain kernel backend.** The current position is that
   multihoming is cradle-only by decision. Is enabling FDB nexthop groups on the
   kernel backend acceptable, with aliasing and mass withdraw but still no
   non-DF or split-horizon filtering when the Linux bridge forwards? It would be
   documented as remote-side only.
4. **Nexthop ID ownership.** Should there be a fixed zebra-rs range for FDB
   nexthop IDs, or should the existing IP nexthop allocator be shared?
5. **HWOL and aliasing (§6.1).** Is part A still worth doing first, knowing
   that load balancing over a remote segment runs in software on an HWOL
   chassis until OVN or OVS changes? And which OVN option should we propose
   upstream: hash fields, offloading `hash`, or a single path per MAC?

---

## References

- [`bgp-evpn-multihoming-dataplane.md`](bgp-evpn-multihoming-dataplane.md) — the
  kernel analysis and the C1–C15 inventory used here.
- [`bgp-evpn-support-status.md`](bgp-evpn-support-status.md) — the multihoming
  and aliasing rows.
- [`bgp-evpn-kernel-integration-tracking.md`](bgp-evpn-kernel-integration-tracking.md)
  — the OVN-facing kernel integration (#2477, #2488, #2502).
- OVN: `NEWS` (dynamic routing, EVPN ECMP/multi-homing FDB),
  `controller/evpn-fdb.c`, `controller/physical.c`
  (`physical_consider_evpn_binding`), `controller/neighbor.c`
  (`dynamic-routing-advertise-ifname`).
- Linux FDB nexthop groups (5.9); bridge `backup_port` / `backup_nhid`
  (`IFLA_BRPORT_BACKUP_NHID`, 6.5).
- OVS: `lib/dpif-offload-tc-netdev.c` (tc flower offload actions),
  `ofproto/ofproto-dpif-xlate.c` (`pick_dp_hash_select_group`, fast-failover
  `watch_port`), `other_config:hw-offload` and `tc-policy`.
- RFC 7432 §8 (multihoming), RFC 8365 §8.3.1 (split horizon by local bias),
  RFC 8584 (DF election framework).
