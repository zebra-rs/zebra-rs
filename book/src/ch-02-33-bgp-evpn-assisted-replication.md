# BGP EVPN BUM & Assisted Replication

zebra-rs forwards EVPN **BUM** traffic (Broadcast, Unknown-unicast,
Multicast) over VXLAN using **ingress replication** (RFC 7432 / RFC 8365),
and optimizes it with **Assisted Replication** and **Pruned-Flood-Lists**
from RFC 9574 ("Optimized Ingress Replication Solution for EVPN").

Where [Type-5](ch-02-06-bgp-evpn-type5.md) is the L3 service, this chapter
covers the L2 broadcast domain: how a VNI's flood list is built from
Type-3 (Inclusive Multicast Ethernet Tag, IMET) routes and programmed into
the Linux VXLAN dataplane.

## Ingress replication (the baseline)

For every locally-configured VXLAN VNI, an `advertise-all-vni` speaker
originates a **Type-3 IMET** route carrying a **PMSI Tunnel attribute**
(tunnel type 6, *Ingress Replication*) whose tunnel endpoint is the local
VTEP. Each remote PE that imports the route is added to the VNI's **flood
list**: the daemon programs a zero-MAC (`00:00:00:00:00:00`) FDB row on the
VXLAN device, one `dst` per remote VTEP:

```
bridge fdb append 00:00:00:00:00:00 dev vxlan10 dst <remote-VTEP> self
```

The kernel then head-end-replicates each BUM frame to every listed `dst`.
With *N* PEs the ingress PE sends *N−1* copies — the cost Assisted
Replication reduces.

```
set vxlan vxlan10 vni 10
set vxlan vxlan10 local-address 10.0.0.1
set router bgp afi-safi evpn advertise-all-vni true
```

## Assisted Replication (RFC 9574)

Assisted Replication offloads the *N*-way fan-out to a dedicated
**AR-REPLICATOR**. RFC 9574 defines three roles, signalled in the Type-3
IMET PMSI Tunnel attribute's *Assisted Replication Type* (T) field:

| Role | T | Behaviour |
| ---- | - | --------- |
| **RNVE** (none) | 0 | Regular NVE — plain ingress replication to every PE. The default. |
| **AR-REPLICATOR** | 1 | Advertises a **Replicator-AR** IMET (PMSI tunnel type `0x0A`) whose next hop is a distinct **AR-IP**; replicates BUM on behalf of leaves. |
| **AR-LEAF** | 2 | Sends one BUM copy to a replicator's AR-IP instead of replicating to every PE. |

The role is configured per speaker under the `evpn` address family:

```
# An AR-REPLICATOR offering its AR-IP 10.0.0.254
set router bgp afi-safi evpn assisted-replication role replicator
set router bgp afi-safi evpn assisted-replication replicator-ip 10.0.0.254

# An AR-LEAF (offloads BUM to a replicator)
set router bgp afi-safi evpn assisted-replication role leaf
```

On the **receive** side the daemon classifies each remote's Type-3 route
(Regular-IR vs Replicator-AR) and builds the flood list according to the
*local* role:

* an **AR-LEAF** collapses its flood list to a **single** zero-MAC FDB row
  toward the chosen replicator's AR-IP (falling back to full ingress
  replication if no replicator is available);
* an **RNVE** / **AR-REPLICATOR** floods to every remote PE's IR-IP.

The collapse is observable in the kernel FDB — an AR-LEAF shows one `dst`
(the AR-IP); an RNVE shows one per remote VTEP.

## Pruned-Flood-Lists

A node that does not want to receive a flood category can ask peers to
prune it, by setting the **BM** (Broadcast/Multicast) and/or **U**
(Unknown-unicast) flags in its own Type-3 IMET:

```
set router bgp afi-safi evpn pruned-flood-list broadcast-multicast true
set router bgp afi-safi evpn pruned-flood-list unknown-unicast true
```

A peer drops the node from the VNI's flood list (omits its FDB row) when it
requests pruning from **both** categories. A single Linux flood list per
VNI cannot express a per-category prune, so a partial (BM-only / U-only)
request is not honored — the node stays in the flood list.

## Selective Assisted Replication

In **selective** mode an AR-REPLICATOR replicates only to the leaves that
explicitly joined its set, rather than to the whole broadcast domain. The
replicator sets the **L** (Leaf Information Required) flag in its
Replicator-AR route; each AR-LEAF responds with a **Leaf A-D** route (EVPN
Route Type 11, RFC 9572) keyed on the replicator's route and scoped to it
with an **IPv4-address-specific Route Target** (`<replicator-NH>:0`):

```
set router bgp afi-safi evpn assisted-replication role replicator
set router bgp afi-safi evpn assisted-replication replicator-ip 10.0.0.254
set router bgp afi-safi evpn assisted-replication selective true
```

The replicator then learns its AR-LEAF set from the imported Leaf A-D
routes (visible as `[11]:` routes in `show bgp evpn`).

## What the Linux kernel can and cannot do

Assisted Replication targets the VXLAN ingress-replication dataplane, where
the kernel imposes hard limits — one flood list per VNI, shared by all BUM
categories, with a fixed outer source IP. The roles map onto a stock kernel
as follows:

| Capability | Stock Linux | Why |
| ---------- | ----------- | --- |
| **RNVE** ingress replication | ✅ | The zero-MAC FDB fan-out. |
| **AR-LEAF** (BUM → one AR-IP) | ⚠️ with unknown-unicast flooding disabled | The single flood list can't split "broadcast → AR-IP, unknown-unicast → IR"; collapsing it to the AR-IP is correct only when unknown-unicast flooding is off (the usual EVPN posture). |
| **Whole-VTEP P-FL prune** | ✅ | Just omit the remote's FDB row. |
| **Per-category P-FL prune** | ⛔ | One flood list per VNI can't keep a remote for broadcast but drop it for unknown-unicast. |
| **AR-REPLICATOR forwarding** | ⛔ | The kernel never re-floods a decapsulated BUM frame back out to other VTEPs, can't branch on the AR-IP vs IR-IP outer destination, and can't rewrite the per-copy source IP — so it cannot act as a replicator. Needs eBPF/XDP or VPP. |

zebra-rs therefore implements the full RFC 9574 **control plane** (role
signalling, P-FL, selective Leaf A-D) and the kernel-supported dataplane
subset (**RNVE**, **AR-LEAF**, whole-VTEP prune). Acting as the
**AR-REPLICATOR** forwarder is out of stock-kernel scope and is deferred to
a programmable dataplane (eBPF/XDP or VPP) — the control plane is the
producer that drives it.
