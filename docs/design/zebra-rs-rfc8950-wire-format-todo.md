---
name: zebra-rs-rfc8950-wire-format-todo
description: Open design questions for the RFC 8950 IPv4-over-IPv6 UPDATE wire format work (the last big piece of BGP unnumbered). Capability negotiation already merged 2026-05-20.
metadata: 
  node_type: memory
  type: project
  originSessionId: e0b3ed88-4da1-4b63-b6c6-cb6b26c49474
---

State as of 2026-05-20: BGP unnumbered is functional for IPv6 unicast (sessions over `fe80::%ifindex` come up via #627 + #628). RFC 8950 capability negotiation lands in the in-flight `ENHE-NEGOTIATE-1` PR — it advertises the cap on OPEN for `PeerOrigin::Interface` peers and sets `UpdateGroupSig::extended_next_hop` when both sides advertised. The remaining work is the actual wire format that lets IPv4 routes traverse the session with a v6 next-hop.

**Why memory:** this PR will be the biggest in the whole feature (estimated 800–1500 lines across emit + receive + RIB integration). The design surface deserves an explicit decision-by-decision walk-through at the start of the implementing session.

**Open design questions** (each "cost of getting wrong" estimated):

1. **Where does the outbound v6 next-hop come from?** *(High cost)*
   - Option A: track per-interface IPv6 addresses in BGP's RIB-LinkAdd handler (BGP already wires `link_index_by_name` from RibRx::LinkAdd; extend to capture per-link `addr6` from the `Link` struct).
   - Option B: query the established TCP socket's `getsockname()` at session-up time — gives us our actual local link-local for this session.
   - Option B is simpler (no new state) but races with `RibRx::AddrAdd` if the address rotates; A is more correct but invasive.

2. **Single vs dual next-hop encoding.** *(Low cost — can extend later)*
   - RFC 8950 §3 allows 16-byte (LL-only or global-only) or 32-byte (global+LL). Default to 16-byte LL-only for v1 — covers every unnumbered deployment. Dual-form is a follow-up.

3. **Dispatch granularity in `pop_ipv4`.** *(Medium cost)*
   - Branch inside the existing `pop_ipv4` on a per-update flag → minimal diff, but the function is already a 60-line state machine.
   - Add a parallel `pop_ipv4_mp_reach` and pick at `encode_ipv4_update` time → cleaner separation, mirrors how `pop_vpnv4` is structured. Probably this.

4. **Receive-side decoder.** *(Medium cost)*
   - `BgpAttr` parsing already handles MP_REACH for other AFI/SAFIs. Confirm whether (AFI=1, SAFI=1, next-hop-len=16 or 32) gracefully flows through the existing IPv4-unicast path or needs a new arm.
   - The 32-byte form needs explicit splitting into global+LL.

5. **Local RIB next-hop resolution.** *(High cost)*
   - An IPv4 prefix with a v6 next-hop installs into the kernel via the nexthop-id mechanism (RFC-style: separate `RTA_NH_ID` referring to a nexthop object whose family is AF_INET6). Whether the existing `rib::resolve` / FIB install paths handle this, or need a new arm.
   - The interaction with `selectroute` / `bestpath` likely doesn't need changes — they're family-agnostic — but worth verifying.

**Suggested PR split** (when picking this back up):
- PR A: per-peer v6 next-hop source (resolve question 1) — pure state plumbing, no wire-format changes yet.
- PR B: emit side. New `pop_ipv4_mp_reach` + dispatch in `encode_ipv4_update` keyed off `UpdateGroupSig::extended_next_hop`. Send-only; testable by capturing emitted bytes against a known-good fixture.
- PR C: receive side. Decoder for v6 next-hop in MP_REACH for IPv4-unicast.
- PR D: local RIB + FIB install with v6 next-hop for an IPv4 prefix.

**Constraints worth remembering at impl time:**
- The legacy NEXT_HOP attribute (code 3) MUST still be emitted with the BGP NEXT_HOP for non-ENHE peers. RFC 8950 ENHE replaces only the MP_REACH next-hop, not the legacy attribute, for ENHE-enabled sessions advertising IPv4 unicast via MP_REACH.
- `extended_next_hop` is a per-(afi,safi,peer) negotiated state — already wired through `UpdateGroupSig`. Wire format must consult the signature, not `peer.cap_send`/`cap_recv` directly, because update-group flushes go through the signature path.
