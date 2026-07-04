# BGP MUP (Mobile User Plane) — user-plane dataplane plan

> **Status:** planning (2026-07-04). This doc splits the one remaining MUP
> dataplane item — the "GTP-U endpoint behaviours" left open in
> [`bgp-mup-followups.md`](bgp-mup-followups.md) §P6 *Remaining* — into two
> independently shippable plans:
>
> - **Plan A — End.DT46 user plane (no GTP dataplane).** Stock Linux; reuses
>   the seg6local `End.DT46` + SRv6 `H.Encaps` primitives already wired.
>   **First priority.**
> - **Plan B — real GTP behaviours via the cradle-rs eBPF dataplane.**
>   `H.M.GTP4.D` / `GTP4.E`, driven over the existing cradle gRPC tee.
>   **Second priority.**
>
> The MUP **control plane is already complete** (P5 controller + P6 slices 1–6;
> see the followups doc). Neither plan touches BGP/PFCP signalling — both are
> purely *forwarding-install* work on top of the finished control plane.

---

## Where we are (shared baseline)

zebra-rs terminates PFCP/N4 as a UP node, models each session, and originates
the full set of MUP routes (ISD/DSD/ST1/ST2). The **only subscriber-traffic
FIB install that exists today** runs on a **receiving interwork/SRGW node** and
programs an SRv6 **`H.Encaps` toward a remote `End.DT46` SID** as a *stand-in*
for the draft's GTP-aware edge behaviours. Concretely:

| Forwarding install | Node role | Driven by | Exists? | Where |
|---|---|---|---|---|
| `End.DT46` `SEG6_LOCAL_VRFTABLE` decap into a VRF | any `encapsulation srv6` VRF | **config** (VRF spawn + kernel table) | **Yes** | `bgp/vrf/spawn.rs:255-271` → `fib/netlink/srv6.rs:289-361` |
| ST2→DSD uplink encap (dst = ST2 endpoint `/32`\|`/128`) | interwork VRF, **received** DSD | received route + NHT transport | **Yes** | `reconcile_mup_st2_dsd` `bgp/vrf/inst.rs:792-854` |
| ST1→ISD downlink encap (dst = ST1 UE prefix) | interwork VRF, **received** ISD | received route + NHT transport | **Yes** | `reconcile_mup_st1_isd` `bgp/vrf/inst.rs:687-754` |
| Per-session downlink encap for the node's **own** UE prefix | co-located MUP-C/UPF | PFCP session | **No** | — |
| N6 breakout (inner IP → data network) | co-located UPF | PFCP / config | **No** | — |
| Real GTP-U decap/encap (`H.M.GTP4.D` / `GTP4.E`) | mobile edge | — | **No** | out of stock-Linux scope |

The install machinery — `mup_encap_install` (`bgp/vrf/inst.rs:862-885`) →
`build_srv6_vpn_fib_entry` (`bgp/route.rs:476-515`) → `Ipv4Add`/`Ipv6Add` —
already produces `dst via <underlay> encap seg6 mode encap segs [End.DT46 SID]`.
The gap is *what triggers it*, not *how to build it*.

**Key fact the co-located node hits today:** a locally-originated ST route,
re-imported into the global MUP RIB, carries `transport = &[]` (a local SID is
on this node, `bgp/route.rs:13245-13256`), and both reconcilers bail on empty
transport (`bgp/vrf/inst.rs:705-707`, `813-815`). So the PFCP-terminating node
installs **nothing per-session** — it only advertises routes and holds the
static, config-driven `End.DT46` decap.

---

## The user-plane forwarding contract (shared)

Everything a MUP-U node must forward, mapped to state we already hold in
`MupSession` (`mup-c/session.rs:14-57`). Both plans satisfy the same contract;
they differ only in the datapath primitive used at the mobile edge.

| Plane | Trigger | Action | Plan A primitive | Plan B primitive | State held |
|---|---|---|---|---|---|
| **Downlink** (core→gNB) | ST1 / access | UE prefix → encap toward access edge | `H.Encaps` → ISD `End.DT46` | `GTP4.E` (IPv4+UDP2152+GTP-U, gNB TEID) | `ue_ipv4/6`, `endpoint`, `teid` |
| **Uplink** (gNB→core) | ST2 / core | decap → route inner in VRF | `End.DT46` `SEG6_LOCAL_VRFTABLE` | `H.M.GTP4.D` on `(core_endpoint, core_teid)` | `core_endpoint`, `core_teid`, NI→VRF |
| **N6 breakout** | inner IP | route inner packet to the DN | VRF FIB route toward `core_endpoint`/N6 | same | VRF table |
| **N9** (later) | UPF↔UPF | GTP-U to peer anchor | (SRv6 segment) | GTP-U | core tunnel |

In **Plan A** the "GTP-U tunnel" is *control-plane metadata only* — the TEID
rides the NLRI for correlation and is never on the wire; the subscriber path is
L3VPN-over-SRv6. In **Plan B** the TEID becomes a real GTP-U header.

---

## Plan A — End.DT46 user plane (no GTP dataplane) — **FIRST PRIORITY**

### Principle

Substitute `End.DT46` for the draft's `End.M.GTP4.D` / `GTP4.E` / `GTP6.E`
everywhere. The mobile fabric carries subscriber traffic as **L3VPN over
SRv6**: the access-side PE encaps into the anchor's `End.DT46` SID, the anchor
decaps into the N6 VRF and breaks out. GTP-U never appears in the datapath.
This is achievable on **mainline Linux** — `End.DT46` maps to kernel seg6local
actions 7/8/16, "already wired" (`bgp-prefix-sid-rfc9252.md:124-159`) — and
reuses every primitive from P6 slices 5–6.

Plan A's job is to make the **co-located PFCP-terminating node forward its own
sessions' subscriber traffic**, which today only a *separate* interwork node
does for *received* routes.

### What already exists (reuse, don't rebuild)

- `End.DT46` decap into the VRF at spawn (`spawn.rs:255-271`).
- `H.Encaps` builder + install (`mup_encap_install`, `build_srv6_vpn_fib_entry`).
- ST↔segment resolution (`reconcile_mup_st1_isd` / `reconcile_mup_st2_dsd`).
- NHT for remote segment next-hops (`nht.rs` `NhtDep::Mup`, followup #2, DONE).

### Plan-A gaps (what to build)

- **A-gap-1 — no local per-session downlink encap.** The session's own UE
  prefix gets an `H.Encaps` only on a separate interwork node (received ST1 +
  covering ISD + non-empty NHT transport). On the origin node the re-imported
  route has `transport = &[]` → no-op.
- **A-gap-2 — no N6 / breakout egress.** `End.DT46` drops the inner packet into
  the VRF table, but nothing routes it toward the data network.
  `session.core_endpoint` (`pfcp.rs:294-297`) is never converted to FIB.
- **A-gap-3 — collocated ingress (gNB-facing) encap.** The uplink ingress encap
  (dst = gNB endpoint) runs only on the interwork node; a node that both
  terminates PFCP and faces the gNB has no ingress-encap install.

### Phases

#### A1 — local per-session downlink encap — *the loop-closer*

For a locally-originated ST1 (and the co-located ST2's endpoint), install the
UE-prefix `H.Encaps` toward the **downlink segment SID** on the origin node
itself, resolving the local transport (the node's own `End.DT46` for the N6
VRF, or a resolvable remote via NHT).

- **Where:** a new same-node reconcile in `bgp/vrf/inst.rs` called from the
  `MupOriginate` handler (`:1939`), **or** extend `dispatch_mup`
  (`bgp/route.rs:13249`) to pass a resolved local transport for `origin_vrf`
  instead of `&[]`. Reuse `mup_encap_install` unchanged.
- **Size:** S–M. First per-session FIB write MUP-C ever makes.

#### A2 — N6 breakout egress

On `SessionUp`, install a VRF route toward `core_endpoint` / the N6 next-hop so
the decapped inner subscriber packet has a path to the data network.

- **Where:** `mup-c/inst.rs` `SessionUp` path, or a new VRF-task install in
  `bgp/vrf/inst.rs`. Withdraw on Session Deletion / AN-release deactivation
  (mirror the #1766 deactivation handling).
- **Size:** S–M.

#### A3 — collocated ingress encap (topology-dependent, optional)

For a node that also faces the gNB, install the ingress SRv6 encap (dst = gNB
endpoint, like `reconcile_mup_st2_dsd`) on the same node, so uplink works
without a separate interwork hop. Skip when the deployment keeps a distinct
access PE.

- **Size:** M.

### Config model

No new grammar required for A1–A2 in the collocated model: a VRF with
`encapsulation srv6` + `afi-safi mup route st1|st2 network-instance <ni>` + an
RD already carries everything. A1 changes *when* the encap fires (local origin,
not only received). Optionally add an explicit `mup dataplane end-dt46` opt-in
so the local-install is gated and the pure-signalling deployments are
unaffected.

### Tests

Extend the existing MUP BDDs (`bgp_mup_st2_dsd_fib`, `bgp_mup_st1_isd`) with an
assertion that the **originating collocated node** (z1) installs its own
UE-prefix `H.Encaps` and an N6 route — assert via `ip -6 route show table all`
in z1's namespace, alongside the existing z2 interwork assertions.

### Limits / non-goals

No GTP-U on the wire; the gNB↔fabric edge must speak SRv6 (or a separate SRGW
does the GTP⇄SRv6 bridge — that's Plan B). No per-QFI, buffering, or usage
reporting. This is an SRv6 L3VPN user plane with MUP control-plane semantics —
not a 3GPP-conformant N3 UPF.

---

## Plan B — real GTP behaviours via cradle-rs eBPF — **SECOND PRIORITY**

### Principle

Implement the draft's GTP-aware edge behaviours (`H.M.GTP4.D` uplink decap,
`GTP4.E` downlink encap) in the **cradle-rs eBPF dataplane**
(`/home/kunihiro/cradle-rs`), and drive them from zebra-rs over the existing
**cradle gRPC tee** (`fib/cradle.rs`). This gives real GTP-U on the wire — a
true SRGW (GTP access ↔ SRv6 core) and, at the far end, a standalone N3 UPF.

### cradle-rs baseline

cradle-rs is a fully-Rust **aya eBPF** L2–L7 dataplane: `cradle_tc` (TC clsact
ingress — L3 forward + **all encap**, `apply_hencap` `crates/cradle-ebpf/src/main.rs:1411`)
staged with `cradle_xdp` (XDP — **all decap / endpoint behaviours**,
`try_srv6_xdp` match `main.rs:1894`). It already implements the full SRv6 suite
(End/DT/DX/uSID/REPLACE/B6/M), MPLS, and EVPN-over-SRv6, driven by the
`cradle.v1.Cradle` gRPC service (`proto/cradle.proto:262-292`). **GTP is
entirely absent** — the only trace is `README.md:91` marking `H.M.GTP4.D /
GTP6.D` "mobile user plane out of scope", *already slotted into cradle's SRv6
mobile-uplane taxonomy* — exactly the reuse seam.

### Two flavours (pick per topology)

- **B1 — SRGW interworking (`H.M.GTP4.D` / `End.M.GTP4.E`).** These drop
  *directly* into cradle's existing SRv6 behaviour dispatch: `GTP4.E` encap
  mirrors `apply_hencap` (`main.rs:1411`) writing IPv4+UDP(2152)+GTP-U+TEID
  instead of IPv6+SRH; `H.M.GTP4.D` decap mirrors `decap_head` (`main.rs:2794`)
  + the `endt_meta` VRF hand-off (`main.rs:2059`). High reuse; classification is
  the outer-IPv6-SID lookup that already exists. This is the **SRGW that bridges
  a GTP access to the SRv6 core** — the natural Plan-A→Plan-B upgrade (swap the
  `End.DT46` stand-in for the real GTP behaviour on the interwork node).
- **B2 — standalone N3 UPF (PDR/FAR).** Terminate GTP-U directly from the gNB:
  classify `(outer-v4-dst, UDP 2152, TEID)` against a **new PDR map** and act on
  a FAR. This is net-new (cradle's endpoint trie `SRV6_LOCALSID` is IPv6-DA
  only, `main.rs:1890`) and is the path that consumes the self-allocated N3/core
  TEIDs as real receive contexts. Larger; a true 3GPP UPF.

### Extension points

**cradle-rs side:**

- **eBPF** (`crates/cradle-ebpf/src/main.rs`): `gtp4e_encap()` modelled on
  `apply_hencap` (`:1411`), wired into `l3_forward_v4:1025` / `l3_forward_v6:1159`
  under a new `NH_F_GTP` flag; `gtp_decap()` modelled on `decap_head` (`:2794`,
  IPv6-gated — needs a v4/UDP/GTP sibling) reached from a GTP classify branch in
  `try_xdp:1585` (B2) or the `try_srv6_xdp` match (`:1894`, B1); new `#[map]`s in
  the map block (`:62-178`, auto-created at load — no loader change).
- **ABI** (`crates/cradle-common/src/lib.rs`): `NH_F_GTP` flag (near `:130-135`);
  a `GtpEncap` value struct modelled on `Srv6Encap` (`:367`) carrying TEID +
  outer v4 addrs; a `PdrKey`/`Far` pair (B2); `STAT_GTP_ENCAP`/`STAT_GTP_DECAP`
  (near `:597`).
- **proto** (`proto/cradle.proto`): GTP fields on `Nexthop` (`:26`) or a new
  `GtpTunnel` message; reuse `LocalSid.behavior` (`:91`) with a new behavior
  code (B1) or add `AddPdr`/`AddFar` RPCs to the service block (`:262`, B2).
- **control** (`crates/cradle/src/control.rs`): extend the behavior whitelist
  `srv6_behavior()` (`:40`) for B1, or add `add_pdr`/`add_far` handlers for B2;
  map writes via `dataplane.rs` (mirror `localsid_add`).

**zebra-rs side:**

- Add GTP variants to `SidBehavior` (`rib/segment_routing/sid.rs:17`) and sweep
  the three consumers: kernel action map `fib/netlink/srv6.rs:119` (return
  unsupported — mainline has no GTP action), `sid_route_target`
  `fib/netlink/handle.rs:242`, and the cradle map `fib/cradle.rs:53`
  (`srv6_behavior`). This is the same pattern the followups doc and
  `bgp-prefix-sid-rfc9252.md` describe for other off-kernel behaviours.
- Drive the behaviour from the MUP install path: B1 swaps the `End.DT46` SID for
  the GTP behaviour in `reconcile_mup_st*` when the peer is a GTP edge; B2 has
  MUP-C drive cradle directly from PFCP PDR/FAR (`mup-c/`), bypassing BGP for the
  local datapath.

### Phases

- **B0 — plumbing.** `SidBehavior` GTP variants + 3-site sweep; proto + ABI +
  whitelist stubs; `NH_F_GTP`. No forwarding yet. Size M.
- **B1 — SRGW behaviours.** `GTP4.E` encap + `H.M.GTP4.D` decap in cradle eBPF,
  dropped into the SRv6 dispatch; zebra-rs drives from the interwork reconcile.
  Size M–L.
- **B2 — standalone UPF.** PDR/FAR classification + maps + RPCs; MUP-C drives
  cradle from PFCP. Size L.
- **B3 (later) — QER/URR/N9.** Rate limiting, usage reporting, UPF↔UPF. Size L+.

### Tests

Clone `cradle-rs`'s `bdd/tests/features/cradle_srv6.feature` into a
`cradle_gtp*.feature` with a gNB/UE ↔ UPF namespace topology, and assert real
forwarding via the gRPC `GetStats` counters (`gtp_encap` / `gtp_decap` nonzero)
exactly as the SRv6 feature asserts `srv6_encap` / `srv6_decap`.

### Limits

Requires the cradle eBPF dataplane deployed on the node (aya/XDP/TC, nightly +
`bpf-linker`), i.e. not stock kernel forwarding. This is the production/scale
path; Plan A is the stock-Linux path.

---

## Sequencing & how A feeds B

1. **Plan A first** — completes a working, stock-Linux SRv6 user plane on the
   collocated MUP-U node (A1 downlink encap + A2 N6 breakout are the minimal
   end-to-end slice). No external dataplane, testable in namespaces today.
2. **Plan B second** — replaces the `End.DT46` stand-in with real GTP behaviours
   where genuine GTP-U interop is required. B1 (SRGW) is a near drop-in on top of
   Plan A's install sites (swap the SID/behaviour); B2 (standalone UPF) is the
   larger PDR/FAR build that finally consumes the self-allocated N3/core TEIDs as
   real forwarding contexts.

Both plans share the control plane and the forwarding contract above, so the
signalling, resolution, and route origination are done regardless of which
datapath a given node runs.

---

## Cross-references

- [`bgp-mup-followups.md`](bgp-mup-followups.md) — control-plane + P6 slices 1–6
  (the End.DT46 stand-in; §*Remaining* is what this doc plans).
- [`bgp-prefix-sid-rfc9252.md`](bgp-prefix-sid-rfc9252.md) — the kernel-support
  boundary (`End.DT46` mainline vs GTP/L2 behaviours needing VPP/eBPF/`End.BPF`).
- `../cradle-rs` — the eBPF dataplane for Plan B (`README.md`,
  `docs/design/architecture.md`, `proto/cradle.proto`).
