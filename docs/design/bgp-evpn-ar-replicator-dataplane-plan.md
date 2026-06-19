# EVPN AR-REPLICATOR Forwarding Dataplane (RFC 9574 Phase 4) — Deferred Design

The RFC 9574 **control plane** (roles, Pruned-Flood-Lists, selective AR) is
built and merged — see
[`bgp-evpn-assisted-replication-plan.md`](bgp-evpn-assisted-replication-plan.md).
This document is the design for the one piece that is **out of stock-kernel
scope and therefore deferred**: making a zebra-rs node act as an
**AR-REPLICATOR forwarder** — receive a BUM packet on its AR-IP, and re-flood
it to the other VTEPs in the broadcast domain.

It is written as a handoff: the control plane is the *producer*; this is the
*consumer* a future programmable dataplane (eBPF/XDP or VPP) would implement.

## Why the stock Linux kernel cannot do this

The Linux VXLAN/bridge datapath gives one flood list per VNI (the zero-MAC
FDB), shared by all BUM categories, with a fixed outer source IP. An
AR-REPLICATOR needs three things the kernel does not provide:

1. **VTEP → VTEP re-flood.** A BUM packet received from a VTEP is decapsulated
   into the bridge, which floods only to *other bridge ports* — never back out
   the ingress port. The VXLAN netdev is both the ingress port and the sole
   overlay egress port, so received BUM reaches local ACs only and is never
   re-encapsulated toward other VTEPs. There is no "replicator" data path.
2. **Per-outer-destination branch.** The driver decapsulates identically
   whether the outer destination was the **AR-IP** (→ replicate to tunnels) or
   the **IR-IP** (→ local delivery only). There is no hook to branch on it.
   (The single-IP / VNI-discriminated RFC variant does not help — the kernel
   will not branch on VNI to re-flood either.)
3. **Per-copy source-IP rewrite.** VXLAN egress source is the device's fixed
   `local` address, so the replicator cannot set the outer source to the
   originating leaf's IP (needed for multihomed-ES split-horizon, RFC 9574
   §6), nor re-originate at all.

This is the same class of gap already documented for the deferred EVPN-SRv6-L2
producer (kernel `seg6local` has no `End.DT2M` "L2 multicast → replicate").

## What the AR-REPLICATOR forwarder must do (RFC 9574 §5–6)

On a packet arriving on the **AR-IP** (VXLAN UDP, VNI `V`):

- decapsulate, deliver to local ACs for VNI `V`;
- replicate to **every other** PE in `V`'s flood domain:
  - to other **AR-REPLICATORs**: outer dst = their **IR-IP** (stops further
    replication);
  - to **AR-LEAF / RNVE**: outer dst = their IR-IP; outer src = own IR-IP
    (MAY preserve the originating leaf's src for ES split-horizon);
- **split-horizon:** never send back toward the source VTEP;
- skip a tunnel flagged `BM=1` for broadcast/multicast and `U=1` for
  unknown-unicast (per-category P-FL);
- **selective mode:** replicate only to the AR-LEAFs in this replicator's
  leaf-set (the Leaf A-D originators), plus RNVEs.

A packet arriving on the **IR-IP** is delivered to local ACs only (normal
ingress replication) — no re-flood.

## The control plane already produces everything this needs

The future dataplane consumes state the merged control plane maintains in
`EvpnFloodState` (on `LocalRib`) per VNI:

| Dataplane input | Control-plane source |
| --------------- | -------------------- |
| The replicator's own **AR-IP** | `assisted-replication replicator-ip` config |
| The **IR-IP list** of every remote PE | `VniFlood.remotes` keys |
| Per-remote **BM/U prune** flags | `RemoteImet.prune` (today coarse; per-category is a refinement) |
| **Selective leaf-set** (which AR-LEAFs joined) | received Leaf A-D (Type-11) routes carrying `<own-NH>:0` RT |
| Which remotes are other **AR-REPLICATORs** vs leaves | `RemoteImet.ar_ip.is_some()` |

So Phase 4 is purely a **southbound** build: a new FIB program that turns this
table into per-VNI replication state, plus the packet-path that executes it.

## Option A — eBPF/XDP/tc (in-kernel programmable)

zebra-rs already ships XDP/aya infrastructure (BFD/STAMP offload), so this
reuses the build toolchain.

- **Attach point:** XDP (or tc-ingress) on the underlay interface that
  receives VXLAN UDP. Match `udp.dport == 4789 && outer.dst == AR-IP`.
- **Replicate:** for each target IR-IP in the per-VNI map, `bpf_clone_redirect`
  (tc) or build N copies (XDP `bpf_xdp_adjust_*` + redirect), rewriting the
  outer IP/UDP header (dst = target, src = own IR-IP or preserved leaf src) and
  recomputing checksums. Source-VTEP match drops the copy toward the ingress
  VTEP (split-horizon).
- **AR-IP/IR-IP branch:** two maps (or a per-dst-IP lookup) select
  replicate-to-tunnels vs local-only.
- **Maps populated from the control plane:** a new `rib::Message` (e.g.
  `ArReplicatorProgram { vni, ar_ip, targets: [{ir_ip, is_replicator, bm, u}], leaf_set }`)
  → a `fib/xdp` handle writes the BPF maps; mirrors how `mdb_add` writes the
  FDB today.
- **Caveats (from the XDP offload notes):** veth needs SKB mode; clone/redirect
  fan-out and per-copy checksum fix-ups are the hard part; `bpf_timer` not
  needed here.

## Option B — VPP (userspace dataplane)

VPP has native L2 flood/replication (`interface_rx_dpo`, `l2-input` flooding —
see the VPP L2-over-MPLS note), which maps directly onto AR replication and
also unblocks the EVPN-SRv6-L2 `End.DT2M` gap.

- **Southbound:** the same per-VNI replication table is pushed to VPP via its
  binary API / a vpp-agent, programming a replication list keyed on the AR-IP
  bridge-domain.
- **Pros:** real per-copy header rewrite + source preservation are first-class;
  highest performance; one dataplane covers AR-REPLICATOR *and* SRv6 L2 BUM.
- **Cons:** a separate dataplane process and packaging; the largest build.

## Suggested phasing (when Phase 4 is picked up)

1. **FIB interface** — the `ArReplicatorProgram` RIB message + a stub
   `fib` handle that logs the desired replication table (no packet path yet).
   Wire it from `EvpnFloodState` on role/leaf-set/flood changes. (Control-plane
   testable in isolation, like the Flowspec Phase-4 stub.)
2. **Dataplane MVP** — non-selective, single-replicator, IPv4 VTEPs, own-IR-IP
   source, split-horizon by source VTEP. eBPF/XDP on veth (lab) or VPP.
3. **Selective + P-FL** — restrict the target set to the leaf-set; honor
   per-category BM/U (this also unblocks per-category P-FL on the *leaf* side,
   currently whole-VTEP only).
4. **Multihomed-ES** — optional source-IP preservation + local-bias.

## Verification

Cannot be a stock-kernel BDD (the whole point). Options: an eBPF/veth lab that
counts replicated copies and checks split-horizon; a VPP lab; or interop
against a hardware/vendor AR-REPLICATOR. The control-plane producer
(`ArReplicatorProgram` emission) *is* unit/BDD-testable independent of the
packet path.

## Related follow-ups (control-plane, not Phase 4)

These were left open by Phases 0–3 and are cheaper than the dataplane:

- **Replicator-AR BGP next-hop = AR-IP (RFC 9574 §4).** Today the EVPN advertise
  path overrides the next-hop to the local VTEP; the AR-IP rides in the PMSI
  endpoint instead. Self-consistent in zebra-rs, but an interop gap.
- **Render the PMSI / AR role in `show bgp evpn`** (currently only the FDB
  reveals AR behavior).
- **Selective AR: join one chosen replicator** (today joins all) + a
  config-change reconcile for the route-triggered Leaf A-D origination.
