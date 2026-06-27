# BGP Prefix-SID over SRv6 (RFC 9252) — Codec Hardening, Treat-as-Withdraw, and the EVPN-over-SRv6 L2 Forwarder Question

Tracks the BGP Prefix-SID attribute (type 40) work for SRv6 services
(RFC 9252, building on RFC 8669). This memo captures **what already
existed**, **what this branch (`bgp-prefix-sid`) adds**, and — most
importantly for anyone picking up the SRv6 **L2** service work — **why
the L2 Service TLV producer is gated on the dataplane, not the codec.**

Read this first if you're touching
`crates/bgp-packet/src/attrs/prefix_sid.rs`, the `Attr::parse_attr*`
machinery in `crates/bgp-packet/src/attrs/attr.rs`, the
`UpdatePacket.treat_as_withdraw` flag, or the SRv6 service producers in
`zebra-rs/src/bgp/{inst,route}.rs`.

Related: [`bgp-mpls-vpn-plan.md`](bgp-mpls-vpn-plan.md) (the MPLS L3VPN
path this mirrors), and the project memory note `zebra-rs-bgp-srv6-l3vpn`
(the 5-phase L3VPN-over-SRv6 plan).
[`bgp-unknown-attribute-handling.md`](bgp-unknown-attribute-handling.md)
covers the general RFC 4271 §9 unrecognized-attribute path that shares
this same `parse_bgp_update_attribute` loop and treat-as-withdraw hook.

## Status (2026-06-08)

| Piece | Where | State |
|-------|-------|-------|
| Prefix-SID attribute codec (RFC 8669 Label-Index / Originator-SRGB) | `prefix_sid.rs` | in `main` (pre-existing) |
| SRv6 **L3** Service TLV (type 5) codec | `prefix_sid.rs` | in `main` (pre-existing) |
| SRv6 **L3** Service producer (L3VPN-over-SRv6, End.DT46) | `inst.rs::srv6_export_nexthop` | in `main` (pre-existing) |
| **Gap 1** — propagation fidelity (preserve unknown sub-TLVs + RESERVED) | `prefix_sid.rs` | **branch `bgp-prefix-sid`** |
| **Gap 2** — malformed detection (§7) + RFC 7606 treat-as-withdraw | `attr.rs`, `update.rs`, `route.rs` | **branch `bgp-prefix-sid`** |
| **Gap 3** — SRv6 **L2** Service producer (EVPN over SRv6) | — | **not started — blocked on dataplane (see below)** |

## Gap 1 — Propagation fidelity (RFC 9252 §2)

RFC 9252 §2 requires that when a speaker re-advertises a route **with the
next hop unchanged**, the SRv6 Service TLVs — *including any unrecognized
sub-TLV / sub-sub-TLV types* — are propagated further, and **all RESERVED
fields MUST be propagated unchanged**.

The original codec decoded only the SID Information sub-TLV (type 1) and
the SID Structure sub-sub-TLV (type 1), **dropped** everything else, and
**re-emitted RESERVED octets as 0**. That breaks bit-exact propagation
through a route reflector.

Fixed in `prefix_sid.rs`:

- New `RawSubTlv { typ, value }` preserves any unmodelled sub-TLV /
  sub-sub-TLV verbatim.
- `Srv6ServiceTlv` gained `reserved` + `unknown_sub_tlvs`;
  `Srv6SidInfo` gained `reserved1`, `reserved2`, `unknown_sub_sub_tlvs`.
- A `Srv6SidInfo::new(sid, flags, behavior, structure)` constructor keeps
  producers terse (zeroed RESERVED, no unknowns) — used by the L3
  producer in `inst.rs` and the test helper in `route.rs`.
- Unknowns re-emit *after* the modelled fields. The sub-TLV list is
  unordered per §2, so this is conformant (not byte-position-preserving,
  but value- and content-preserving, which is what the RFC mandates).

The SID Structure sub-sub-TLV is now decoded **only at its exact 6-octet
length and only for the first instance**; any other length (or a second
type-1) is preserved as a `RawSubTlv` so the round-trip stays exact.

## Gap 2 — Malformed detection + RFC 7606 treat-as-withdraw

### Codec (`prefix_sid.rs`)

RFC 9252 §7 deems a SID Information sub-TLV malformed when its Value is
shorter than the fixed 21-octet head (RESERVED1 + SID + Flags + Behavior
+ RESERVED2). The parser now rejects that explicitly. Semantic checks the
RFC says are **not** malformations (unknown behavior, AL/transposition
sanity) are deliberately *not* enforced at the codec layer — RFC 9252 §7
says "not malformed because of failing any semantic validation."

### Parse recovery (`attr.rs`)

Previously **any** attribute Value-parse error propagated out of
`parse_bgp_update_attribute` → `parse_packet` → the read loop, which
tears the **whole BGP session** down. RFC 8669 §5 + RFC 9252 §7 (and
RFC 7606 generally) require a malformed Prefix-SID to be
**treat-as-withdraw**, not a session reset.

`Attr::parse_attr` was split so a Value error is recoverable:

- `parse_attr_header` — parses flags/type/length and splits the Value;
  the next-attribute pointer is known **before** the Value is parsed. A
  framing error here is still fatal (RFC 7606 §4 attribute-length error).
- `parse_attr_value` — parses the Value; **recoverable**.
- `attr_malformation_is_withdraw(attr_type)` — currently `true` only for
  `PrefixSid`. Other attributes keep their existing session-reset
  behavior (intentionally minimal — this is not a general RFC 7606
  framework, just the slice RFC 9252 mandates).

On a recoverable error the malformed attribute is discarded and a
`treat_as_withdraw` flag is set; parsing of the remaining attributes
continues. The flag rides on `UpdatePacket.treat_as_withdraw`
(`#[nom(Ignore)]`, not a wire field).

### Withdraw routing (`route.rs::route_from_peer` + `withdraw_mp_reach`)

When `treat_as_withdraw` is set, every **reachable** NLRI in the UPDATE is
routed through its `*_withdraw` path instead of being installed, while the
UPDATE's explicit withdrawals are still honoured and the session stays up.
`withdraw_mp_reach` mirrors the install match across all MP_REACH
families (v4, VPNv4/6, EVPN, v4-over-v6, v6, labeled v4/v6, flowspec,
SR-policy, BGP-LS); RTC and any family that cannot carry a Prefix-SID fall
through a no-op catch-all.

### Tests

`prefix_sid.rs`: bit-exact preservation of RESERVED + unknown sub-/
sub-sub-TLVs; struct round-trip with unknowns; under-length SID-info
rejection. `attr.rs`: a malformed Prefix-SID after a valid ORIGIN yields
`Ok(.., treat_as_withdraw=true)` with ORIGIN surviving and the Prefix-SID
discarded (not a parse failure).

## Gap 3 — SRv6 L2 Service producer: blocked on the dataplane, not the codec

The SRv6 **L2** Service TLV (type 6) codec already exists. The blocker for
a *producer* is that the EVPN L2 services it signals are **not forwardable
by the stock Linux kernel**. This is the SRv6 mirror of the
already-recorded fact that EVPN/MPLS **L2** forwarding needs VPP, not the
kernel.

### What the kernel `seg6local` gives us

Today `zebra-rs` models only L3/transit behaviors
(`SidBehavior` in `rib/segment_routing/sid.rs`: End, End.X, uN, uA,
End.DT4, End.DT6, End.DT46, End.B6.Encaps), and
`fib/netlink/srv6.rs::seg6local_action` maps them to the kernel actions.
Mapping the mainline `SEG6_LOCAL_ACTION_*` set onto EVPN-over-SRv6
(RFC 9252 §6):

| EVPN service | RFC 9252 behavior | Mainline kernel `seg6local`? |
|---|---|---|
| Type-5 IP Prefix (**L3**) | End.DT4 / End.DT6 / End.DT46 | ✅ actions 7/8/16 — **already wired** |
| VPWS point-to-point (Type-1/2) | **End.DX2** | ⚠️ decap exists (action 4 → `oif`); no native ingress L2→SRv6 encap |
| ELAN bridged unicast (Type-2 MAC/IP) | **End.DT2U** | ❌ absent from mainline |
| BUM flooding (Type-3 IMET) | **End.DT2M** (+ Arg.FE2 ESI filtering) | ❌ absent from mainline |

Two distinct gaps for L2:

1. **Egress decap** — the kernel has `End.DX2` (cross-connect to an
   interface) but **no `End.DT2U` / `End.DT2M`**: no "decap → bridge FDB
   lookup" and no "decap → flood to EVI bridge ports." ELAN is the common
   EVPN case and it is simply not in the kernel.
2. **Ingress encap** — `encap seg6` (H.Encaps) is an **L3** lwtunnel on
   IPv6 routes. There is no native `H.Encaps.L2`: no clean,
   control-plane-programmable way to push an Ethernet frame from an
   attachment circuit / bridge port into SRv6. So even VPWS (End.DX2) is
   only half-forwardable on mainline.

### Forwarders that *can* do EVPN-SRv6 L2

- **VPP** — has End.DT2U/DT2M/DX2 and L2 SRv6 encap. Realistic forwarder
  for EVPN-SRv6-L2; a new VPP binary-API southbound, same shape as the
  MPLS-L2 discussion.
- **eBPF via `End.BPF` (action 15)** — attach a custom eBPF program as the
  seg6local action and implement DT2U/DT2M yourself. The `offload/` XDP
  tree makes this plausible, but it is a *custom* dataplane, not the stock
  kernel forwarder.

### Decision menu for Gap 3

A kernel-targeted EVPN-over-SRv6 **L2** producer would be
**control-plane-only** (advertise/receive the L2 Service TLV + Loc-RIB,
but the kernel can't forward ELAN/BUM — only L3, and awkwardly
VPWS-decap). That matches the project's control-plane-first precedent
(Flowspec, SR-Policy, Labeled-Unicast all landed that way), but should be
chosen deliberately:

1. **Control-plane-only L2 producer** — codec + producer/consumer +
   Loc-RIB + show; dataplane deferred to a future VPP/eBPF southbound.
2. **Pivot to VPP/eBPF** for a forwardable L2 — much larger, new
   southbound.
3. **Stop at L3** — keep the value where the kernel forwards today
   (L3VPN + EVPN Type-5, both already working); the L2 producer is a
   future feature.

## Files touched (branch `bgp-prefix-sid`)

- `crates/bgp-packet/src/attrs/prefix_sid.rs` — Gap 1 + Gap 2 codec.
- `crates/bgp-packet/src/attrs/attr.rs` — `parse_attr` split,
  `attr_malformation_is_withdraw`, treat-as-withdraw flag threading.
- `crates/bgp-packet/src/update.rs` — `UpdatePacket.treat_as_withdraw`.
- `zebra-rs/src/bgp/inst.rs` — adopt `Srv6SidInfo::new`.
- `zebra-rs/src/bgp/route.rs` — `route_from_peer` treat-as-withdraw branch
  + `withdraw_mp_reach`.
