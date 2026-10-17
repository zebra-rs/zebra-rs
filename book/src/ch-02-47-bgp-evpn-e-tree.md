# EVPN E-Tree (RFC 8317)

An E-Tree is an E-LAN with two kinds of attachment circuit (AC). A **root**
reaches every other AC. A **leaf** reaches the roots only: two leaves never
exchange a frame, whether they are on the same PE or on different PEs, and
whether the frame is known unicast or broadcast, unknown unicast and multicast
(BUM). The usual uses are hub-and-spoke services: one or more hubs (roots) and
many sites (leaves) that must not see each other.

| From \ To | Root | Leaf |
|---|---|---|
| **Root** | ✅ | ✅ |
| **Leaf** | ✅ | ❌ |

zebra-rs builds E-Tree the way RFC 8317 recommends for every scenario: the
role is set **per AC**, so one EVI on one PE can mix roots and leaves, and
every PE keeps a single route target per EVI. A MAC learned on a leaf AC is
advertised with the E-Tree extended community. A PE that knows nothing about
E-Tree puts no community on its routes, so all its ACs are roots, and that is
correct.

> **This needs the cradle eBPF data plane.** The Linux bridge cannot drop a
> frame by the colour of its destination MAC, cannot carry a leaf mark across
> the core, and cannot tell a leaf's BUM from a root's. A commit that names a
> leaf AC without `system ebpf enabled` or `system cradle enabled` is refused:
>
> ```
> etree leaf-interface ce2: E-Tree needs the cradle data plane (`system ebpf enabled` or `system cradle enabled`); the kernel bridge cannot keep leaves apart
> ```
>
> A startup configuration with the same problem, or one read with `load`, only
> produces a warning, so the router still comes up configured. The check looks
> at the whole configuration, though, so every later commit is refused until
> the leaf AC or the cradle switch is fixed.

## Configuration

```
system {
  ebpf {
    enabled true;
  }
}
interface ce1 {
  ebpf {
    enabled true;
  }
}
interface ce2 {
  ebpf {
    enabled true;
  }
}
interface core0 {
  ebpf {
    enabled true;
  }
}
router bgp {
  global {
    as 65001;
  }
  afi-safi evpn {
    advertise-all-vni true;
    etree {
      leaf-interface ce2;
    }
  }
}
```

`leaf-interface` names a leaf AC by interface. Every AC that is not listed is
a root. A PE whose ACs are all roots needs no E-Tree configuration at all:
it neither drops nor marks anything.

Attach every AC, roots and leaves, to cradle with `interface <name> ebpf
enabled`, and the core-facing interface too (`core0` above). cradle filters
both on the AC a frame enters by and on the core interface a remote PE's copy
arrives on. The commit check only looks for `system ebpf enabled` or `system
cradle enabled`, so it does not catch a missing interface. Under the managed
engine, a leaf AC left out is held and passes no traffic (see below); a root
left out is switched by the Linux bridge, outside cradle's filters.

### What an AC is

An AC is a port of the EVI's bridge: the interface the CE is attached to,
enslaved to the same Linux bridge as the EVI's VXLAN device (or, under
`encapsulation mpls`, the bridge named by `evi <id> { bridge <name>; }`). A
leaf AC's EVIs are the bridges it is a port of.

Bridge every AC. zebra-rs learns an EVI's ACs from the kernel bridge, as the
cradle supervisor does when it binds the ports. A port that is in the cradle
domain without being in the bridge is invisible to zebra-rs. Under VXLAN that
matters (see [VXLAN](#vxlan)): a root zebra-rs cannot see makes the EVI look
leaf-only.

### Changing a role

Adding or removing a `leaf-interface` re-advertises the MACs already learned
on that AC, with or without the leaf flag. It is an attribute change, not a
MAC move, so the MAC Mobility sequence number stays the same.

cradle never switches a leaf as a root. The cradle supervisor sends a port's
role to the engine before it attaches the port, and leaves a leaf unattached
until the engine has acknowledged the role. A managed engine that restarts
gets every role back before its ports. zebra-rs does not see an external
engine (`system cradle enabled`) restart, and a port that an external engine
attaches itself gets its role when zebra-rs sends it.

A port cradle has not attached is switched by the Linux bridge, which knows
no roles. That covers a leaf whose role the engine has not acknowledged
(`show ebpf` says `held (E-Tree leaf role pending)`), every port while the
managed engine is down or starting, and every port at boot before cradle
starts. So zebra-rs also guards each leaf AC in the bridge:

* **`isolated on`, always** (`bridge -d link show` shows it). The bridge
  never switches one isolated port to another, so whenever the bridge rather
  than cradle switches a leaf, it still keeps it from the other leaves.
* **Held in the `listening` state** while cradle should switch the leaf and
  has not attached it with its role. A listening port neither learns nor
  forwards, so nothing reaches or leaves the leaf through the bridge, toward
  a remote leaf included. It goes back to `forwarding` once cradle has it.

With the managed engine (`system ebpf enabled`), a leaf AC without
`interface <name> ebpf enabled` is never attached, so it stays held and passes
no traffic. With an external engine (`system cradle enabled`), such a port is
one the engine may attach by itself, and zebra-rs cannot know whether it has,
so it gets only the isolation. Removing a `leaf-interface` undoes both.

> **What is left.** The bridge returns a port to forwarding when its carrier
> or the bridge itself comes back up, and zebra-rs then holds it again a
> moment later. At boot, a bridged leaf is unguarded until zebra-rs has
> started. Bring leaf ACs up after zebra-rs if those moments matter.

## What zebra-rs advertises

| Route | When | What it carries |
|---|---|---|
| **Type-2** (MAC/IP) | the MAC was learned on a leaf AC | E-Tree EC with the Leaf flag (`etree:leaf`) |
| **Type-1** Ethernet A-D per ES, **ESI 0** (the leaf-label route) | an EVI on this PE has a leaf AC, and this PE has a leaf label (MPLS) or a leaf argument (SRv6); never under VXLAN | E-Tree EC; the route target of every EVI with a leaf AC; MPLS: this PE's leaf label (`etree:leaf-label:<n>`); SRv6: this PE's leaf argument, in an SRv6 L2 Service SID |
| **Type-3** (IMET) | VXLAN, and every AC of the EVI on this PE is a leaf | E-Tree EC with the Leaf flag and no label (`etree:leaf`) |

The leaf-label route is RFC 8317 §4.2.1's. It is keyed like any per-ES A-D
route, with ESI 0 and the MAX-ET Ethernet tag, under RD `<router-id>:0`. One
route carries at most 256 route targets, because an UPDATE without the
Extended Message capability (RFC 8654) is limited to 4096 bytes; more leaf
EVIs spread over further routes under RDs `<router-id>:1`, `<router-id>:2` and
so on. An Ethernet Segment cannot be configured with ESI 0 (or MAX-ESI): RFC
7432 reserves both, and the commit is refused. A startup configuration with
either only produces a warning, and the segment is left without an ESI.

## Who drops what

| Traffic | Dropped where | Encapsulations |
|---|---|---|
| leaf → leaf on the same PE, unicast and BUM | the PE itself | all |
| leaf → a known MAC behind a leaf on another PE | the **ingress** PE, before encapsulation | all |
| leaf BUM → leaves on other PEs | the **egress** PE, or the ingress PE leaves the copy out (VXLAN) | per encapsulation, below |
| anything from a root | nowhere | all |

Known unicast is dropped where it enters: the leaf flag of the destination
MAC's Type-2 says whether the destination is a leaf. The flag is read from the
*selected* route only. MAC mobility decides where a MAC is before anything
decides whether it is a leaf (RFC 8317 §4.1). So when a host moves from a leaf
AC to a root AC, the leaves can reach it as soon as the move is selected.

BUM cannot be dropped at the ingress PE, because one copy toward a PE serves
that PE's roots and leaves alike. So a leaf's BUM is marked as coming from a
leaf, and the egress PE delivers a marked copy to its roots only. How the mark
travels depends on the encapsulation.

### MPLS

This is RFC 8317 §4.2 as written. Each PE with a leaf AC allocates one **leaf
label** from its service labels and advertises it on the leaf-label route.
The label installs no MPLS route of its own: the cradle data plane recognises
it under the BUM label.

* A copy of a leaf's BUM toward a PE that advertised a leaf label carries that
  PE's leaf label under the BUM label. The receiving PE delivers it to its
  roots only.
* A copy toward a PE that advertised no leaf label is sent unmarked: that PE
  has no leaves.
* On a multihomed leaf the leaf label **replaces** the ESI label (RFC 8317
  §4.2.3). The leaf label alone keeps the copy off the segment's other leaf
  ACs, and a root on the segment is the role conflict described below.

The leaf label is held only while the encapsulation is MPLS and some EVI has a
leaf AC. It is released when the last one goes.

### VXLAN

VXLAN has no label to carry the mark, and there is no standard for E-Tree BUM
over VXLAN. zebra-rs uses the wire format of Arista's expired
draft-bamberger-bess-imet-filter-evpn-etree-vxlan, plus one egress rule of its
own:

* A PE whose ACs in an EVI are **all leaves** (a *leaf-only* PE) puts the
  E-Tree EC on that EVI's IMET.
* A leaf's BUM is not sent to leaf-only PEs at all: they have only leaves.
* BUM arriving from a leaf-only PE's VTEP is delivered to roots only, since it
  can only have come from a leaf.

That is exact unless **two or more PEs in the EVI are mixed**, with roots and
leaves both. A mixed PE's IMET has to say "root", so leaf BUM from one mixed
PE to another looks like root BUM and reaches the other's leaves. `show bgp
evpn etree` names each EVI where it has seen this. This PE counts as mixed
from its own configuration. A remote PE counts as mixed only once it has
advertised a MAC from a leaf AC without a leaf-only IMET:

```
  Warning: EVI 10: leaf BUM not isolated between mixed PEs: local, 192.168.0.3
```

Keep the roots and leaves of an EVI on separate PEs where you can. One mixed
PE per EVI is still exact.

The newer draft-ietf-bess-rfc8317bis proposes a second *leaf VNI* in the
IMET's E-Tree EC instead. Its IMET is not wire-compatible with the Arista
form, the draft has expired, and no implementation of it is known. zebra-rs
does not implement it, and treats such an IMET as coming from a root.

### SRv6

The mark is an **argument** of the egress PE's End.DT2M SID (RFC 9252 §6.3,
with RFC 9819's placement). Each PE with a leaf AC uses the leaf argument 1,
16 bits long, placed right after the SID's function.

* For each EVI with a leaf AC, the End.DT2M SID is installed so that it
  accepts an argument, and the IMET advertises an argument length of 16.
  Every other EVI keeps its SID and its IMET exactly as without E-Tree.
* The leaf-label route carries the E-Tree EC with no label, and an SRv6 L2
  Service SID (End.DT2M) whose only bits are the leaf argument, at its
  offset after the block, node and function. Nothing is transposed.
* A copy of a leaf's BUM toward a PE that advertised a leaf argument is sent
  to that PE's End.DT2M SID with the argument in place. The receiving PE
  delivers it to its roots only. A copy carrying any other non-zero argument
  is dropped.

The locator must leave room for the argument: its block, node and function
bits plus 16 must fit in 128. With a locator that does not, the PE has no
leaf argument (`Leaf argument: none` in `show bgp evpn etree`), and leaf BUM
from other PEs reaches its leaves.

A PE whose IMET argument length differs from the one on its leaf-label route
gets no marked copy, so its leaves receive the leaves' BUM. RFC 9819 says not
to forward to such a PE at all; zebra-rs cannot withhold a leaf's BUM from a
single PE over SRv6 yet.

## Multihomed leaves

For a CE multihomed on an Ethernet Segment, name the segment's interface (the
bond, for example) as the leaf AC, on **every** PE of the segment:

```
router bgp {
  afi-safi evpn {
    ethernet-segment ES1 {
      esi 00:11:22:33:44:55:66:77:88:99;
      interface bond0;
    }
    etree {
      leaf-interface bond0;
    }
  }
}
```

RFC 8317 §4.2.3 assumes an AC has the same role on every PE of its segment.
Nothing on the wire says what role a segment's AC has, so nothing can enforce
it. What a mismatch does depends on the encapsulation:

* **MPLS.** A leaf's BUM copy toward a PE with a leaf label carries that label
  instead of the ESI label. If that PE's AC on the segment is a root, it sends
  the copy back into the segment it came from: a loop.
* **VXLAN and SRv6.** Split horizon by the copy's source address still keeps
  it out of the segment, so there is no loop. The PEs still disagree on
  whether the CE is a leaf, so leaves can reach it through the PE where its
  AC is a root.

zebra-rs can detect the mismatch, but only once a peer has advertised a MAC on
the segment. If a peer advertises MACs carrying the segment's ESI with the
other role, `show bgp evpn etree` says so:

```
  Warning: ESI 00:11:22:33:44:55:66:77:88:99: role conflict: our AC bond0 is a leaf, 10.0.0.12 advertise its MACs as root
```

The conflict is also logged once when it starts (warning) and once when it
clears (info).

## Show

```
> show bgp evpn etree
EVPN E-Tree (RFC 8317)
  Leaf interfaces: 1
    ce2              ifindex 7      EVI 100        local MACs 1
  Remote leaf MACs:
    EVI 100        2
  Leaf label:      100021
  Remote leaf labels:
    10.255.0.2       100018
```

* **Leaf interfaces.** Each leaf AC, its EVIs and the MACs learned on it.
  `link absent` means the interface has not appeared yet, and `EVI -` that it
  is not a port of any EVI's bridge.
* **Remote leaf MACs.** Per EVI, the remote MACs behind a leaf: the ones a
  local leaf may not reach.
* Then, depending on the encapsulation:
  * MPLS: this PE's leaf label and each remote PE's.
  * VXLAN: this PE's leaf-only EVIs, the leaf-only remote PEs per EVI, and the
    mixed-PE warning.
  * SRv6: this PE's leaf argument and each remote PE's, with its length.
* **Warnings.** Mixed PEs (VXLAN), a role conflict on a segment, and IRB:

  ```
    Warning: EVI 100: IRB on bridge br100: leaves can reach each other through L3
  ```

  E-Tree is a Layer 2 property. A leaf AC's bridge with a routable address (a
  link-local IPv6 address does not count) or under a VRF routes between
  leaves, and E-Tree does not filter routed traffic. The warning is there so
  this is a choice and not an accident.

`show bgp evpn etree json` gives the same data as JSON.

Elsewhere:

| Command | What it shows |
|---|---|
| `show bgp evpn` | the community on each route: `etree:leaf` (Type-2, VXLAN IMET), `etree:leaf-label:<n>` (MPLS leaf-label route), `etree:-` (SRv6 leaf-label route, whose community carries no label: the argument is in the SID) |
| `show l2 mac table` | flag `L` on a remote MAC behind a leaf |
| `show ebpf` | `E-Tree leaves:` with `(pending)` after a role the engine has not acknowledged, and a port `held (E-Tree leaf role pending)` |
| `show ebpf l2` | `etree-leaf` on a remote MAC behind a leaf |
| `show ebpf stats` | the drop and mark counters below |

| Counter | Counts |
|---|---|
| `l2_drop_etree_local` | leaf → leaf on this PE, dropped |
| `l2_drop_etree_uc` | leaf → known remote leaf MAC, dropped at ingress |
| `l2_drop_etree_bum` | a leaf's BUM from another PE, kept off a local leaf |
| `mpls_l2_leaf_push` | MPLS copies sent with a leaf label |
| `mpls_l2_leaf_pop` | MPLS copies received with this PE's leaf label |
| `srv6_l2_leaf_decap` | SRv6 copies received with this PE's leaf argument |
| `srv6_drop_arg` | SRv6 copies received with an unknown argument, dropped |

## What a receiver accepts

* A route without the E-Tree EC is a root's. A route zebra-rs cannot classify
  never causes a drop.
* A Type-2 carrying the EC without the Leaf flag is invalid under RFC 8317.
  It is logged and treated as a root's.
* A leaf-label route with a reserved MPLS label (0–15) is logged and ignored.
* A leaf-label route whose SRv6 SID gives no usable argument is logged and not
  used: the argument is transposed, the SID has no structure, the argument
  length is 0, or the argument is 0.
* An IMET with the rfc8317bis leaf VNI is a root's (see [VXLAN](#vxlan)).
* A composite PMSI tunnel type (RFC 8317 §6.2) is treated as a malformed PMSI
  Tunnel attribute: the UPDATE's routes are withdrawn, and the session stays
  up. zebra-rs never originates it.

## Not supported

* **The kernel data plane.** Refused at commit (above).
* **Roles per MAC** on one AC (RFC 8317 §3, scenario 3).
* **P2MP tunnels** and **Assisted Replication** (RFC 9574) for an E-Tree
  EVI. Neither is refused or warned about, but a leaf's BUM sent over either
  is not marked, so it reaches the leaves on other PEs. Use ingress
  replication.
* **VPWS.** E-Tree is an E-LAN service. A `leaf-interface` naming a VPWS AC
  is accepted and has no effect.
* **Route-target-based E-Tree** (RFC 8317 approach A, with separate leaf and
  root RTs) is plain route-target configuration and needs no E-Tree code.

## Interoperability

FRR has no E-Tree. Nokia SR OS and Juniper Junos document E-Tree over MPLS,
and Arista EOS documents it over VXLAN with the IMET form used here. That
comes from their documentation: zebra-rs has been tested only against
zebra-rs so far.
