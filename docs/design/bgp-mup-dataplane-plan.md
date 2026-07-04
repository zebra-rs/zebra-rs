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

Plan A's job is to prove the **PFCP-terminating node forwards its own sessions'
subscriber traffic** end-to-end over `End.DT46`.

### What already exists (reuse, don't rebuild)

- `End.DT46` decap into the VRF at spawn (`spawn.rs:255-271`).
- `H.Encaps` builder + install (`mup_encap_install`, `build_srv6_vpn_fib_entry`).
- ST↔segment resolution (`reconcile_mup_st1_isd` / `reconcile_mup_st2_dsd`).
- NHT for remote segment next-hops (`nht.rs` `NhtDep::Mup`, followup #2, DONE).

### Verified findings (2026-07-04) — the per-session install already works

An earlier draft of this plan (following an imprecise investigation summary)
claimed the PFCP-terminating node "installs nothing per-session". **That is
wrong** — verified by running the BDDs against the tree:

- **The origin/UPF node installs its own encap.** `reconcile_mup_st1_isd` /
  `reconcile_mup_st2_dsd` gate on the *segment's* resolved transport
  (`mup_segment_transport`), **not** the ST route's. The node's own ST route
  re-imports into its per-VRF MUP RIB (carrying `mup_st1`) and the reconcile
  installs the encap as soon as a covering **remote** segment (imported by RT)
  resolves via NHT. The `transport = &[]` on the re-imported ST route is
  irrelevant to that gate. `bgp_mup_st1_isd` already proves the UPF+MUP-C node
  (z2) originates the ST1 *and* installs the UE-prefix `H.Encaps` itself.
- **Real packets forward end-to-end.** The new `@bgp_mup_forwarding` BDD drives
  a bidirectional `ceA↔ceB` ping through the `End.DT46` datapath (downlink and
  uplink), passing on the first run — not just route presence, actual ICMP.

So the "A1 — local per-session downlink encap" gap the earlier draft posited is
**already implemented (DONE)**, and A2/A3 are not shaped the way it assumed.

### One real structural constraint

`mup_session_targets` (`bgp/vrf/inst.rs:468`) reads a **single** `srv6_mobile`
binding per VRF, so **a VRF carries exactly one MUP direction** (st1 *or* st2).
A single anchor VRF therefore cannot do both the downlink encap and the uplink
decap for one subscriber: a *bidirectional* subscriber path is realized by two
collocated ST2 anchors (each terminating one host), as `@bgp_mup_forwarding`
does, not by one anchor VRF. Lifting this — one VRF binding both directions —
is the only genuine code change Plan A could still make, and it is optional
(the two-node model forwards correctly today).

### A2 — N6 breakout egress (config, not per-session code)

The remaining honest gap is N6 egress: after `End.DT46` decap the inner packet
is in the VRF table, but reaching an arbitrary **data network** needs a route
out of the VRF. This is **operator config** (a per-VRF default/static route, or
redistribution of the DN prefix), *not* a per-session PFCP-derived install —
and note `session.core_endpoint` is the **ST2 core-tunnel endpoint**, not the
N6 DN gateway, so routing toward it is not "breakout". If a per-session N6
route is ever wanted, its semantics (target next-hop, config vs PFCP-derived)
need a product decision first; `router static vrf` covers the lab case today.

### Tests

`@bgp_mup_forwarding` (`bdd/tests/features/bgp_mup_forwarding.feature`) — two
collocated UPF+interwork nodes, each originates an ST2 (endpoint = a host
behind it) + a DSD from a PFCP session, imports the other's, installs the
ST2→DSD encap, and a bidirectional `ceA↔ceB` ping traverses the `End.DT46`
datapath both ways. Run live via `make -C bdd bgp_mup_forwarding` (root netns).
Complements `bgp_mup_st2_dsd_fib` / `bgp_mup_st1_isd` (which assert the install;
this drives real traffic through it).

### Limits / non-goals

No GTP-U on the wire; the gNB↔fabric edge must speak SRv6 (or a separate SRGW
does the GTP⇄SRv6 bridge — that's Plan B). No per-QFI, buffering, or usage
reporting. A single VRF binds one MUP direction (above). This is an SRv6 L3VPN
user plane with MUP control-plane semantics — not a 3GPP-conformant N3 UPF.

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
