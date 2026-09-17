# BGP-LS feed review

Reviewed `09b6fc6fc5b5a5a39c8fcc19f3b2c6e15c1be995` on 2026-09-17. Scope: IS-IS producer delivery, local origination, initial synchronization, per-peer UPDATE construction, receive/withdraw handling, and collector coverage. Implementation source was not changed.

## Resolution

All four findings are fixed on branch `bgp-ls-egress`.

| # | Finding | Fix |
|---|---|---|
| 1 | Feed lacked peer-specific path attributes | Originated rows now carry ORIGIN and an empty AS_SEQUENCE; `bgpls_egress_attr` prepends our AS toward an external peer and supplies LOCAL_PREF toward an internal one, on both the delta and the initial-dump path |
| 2 | Outbound policy bypassed | `bgpls_policy_out` on both paths |
| 3 | Route Refresh did not replay | `route_soft_out_peer` ends with `route_sync_bgpls` |
| 4 | Serialization exceeded the negotiated limit | Both builders compare the framed length against `max_packet_size` and return `None` rather than hand back an illegal message |

Two notes on where the fix differs from the suggestion:

- **Finding 2** honours the binding, not the match clauses. A Link-State
  NLRI is a descriptor set, not an IP prefix, so the prefix, community
  and AS-path clauses have nothing to test and no prefix is invented to
  give them one. Only an unconditional clause decides; a policy whose
  clauses all carry match conditions falls through to the implicit deny.
  That closes "an accepted deny does nothing" without pretending to
  Link-State matching, which remains a separate extension. Per-peer
  tracking of accepted objects — so a permit-to-deny edit withdraws what
  was already sent — is *not* implemented: there is no Adj-RIB-Out here,
  and the change takes effect on the next refresh or delta.
- **Finding 4** drops an oversized object rather than splitting. Batching
  only helps multiple NLRIs, and these builders emit one NLRI per
  message, so an object whose attribute alone exceeds the limit can
  never be framed legally. The queue is drained either way, since
  retrying would rebuild the same message forever.

The BDD collector is now external (AS 65072) and enforces first-AS, so
the session itself is the gate on finding 1: an empty AS_PATH is
rejected and nothing arrives. Mutation-tested — removing the AS prepend
fails two steps.

### Accepted corrections

The review is right that the `+2 more` assertion counts TLVs rather than
decoding them, and that the BGP-LS attribute codec stores TLV values
opaquely. The claim in `09b6fc6f`'s message that the collector validates
the ASLA internals overstates it: what the collector establishes is that
TLV 1122 *transits* a real UPDATE intact and that the top-level RFC 8571
attributes decode to the delays that went in. The nested masks and
metrics inside 1122 are still unit-tested only, and decoding them needs
a BGP-LS ASLA parser that does not exist.

Also still uncovered, as the review notes: topology withdrawal,
attribute change, reconnect, and an explicit late-peer scenario.

## Findings

### 1. P1 — Feed advertisements lack peer-specific path attributes

Location: [route.rs](../../zebra-rs/src/bgp/route.rs:11268), `bgpls_origin_reach` and `route_sync_bgpls`.

Both paths serialize the stored attribute unchanged. `route_bgpls_originate` creates it with `BgpAttr::new()`: empty AS_PATH and no LOCAL_PREF. `peer.update_packet()` only sets the negotiated packet limit and ASN width; it does not transform attributes. Consequently external peers receive an empty AS_PATH, while internal peers receive no LOCAL_PREF.

[RFC4271 section 5.1.2](https://www.rfc-editor.org/rfc/rfc4271.html#section-5.1.2) requires a locally originated route sent to an external peer to contain the local AS in an AS_SEQUENCE. [Section 5.1.5](https://www.rfc-editor.org/rfc/rfc4271.html#section-5.1.5) requires LOCAL_PREF for internal advertisements. A controller enforcing first-AS rejects the external feed; this repository's `route_bgpls_update` also rejects the empty path when `enforce-first-as` is enabled.

Reproduction: use different ASNs for producer and collector and enable first-AS enforcement on the collector. Initial and subsequent topology announcements have the wrong AS_PATH. The new BDD collector uses the same AS 65071 as its producer, so it does not cover this failure; its permissive receiver also does not establish third-party acceptance of the missing internal LOCAL_PREF.

Apply the session's egress attribute transformation before serialization in both the delta and initial-dump paths, respecting local-AS/confederation settings and negotiated ASN width. Verify iBGP and eBGP wire attributes, including a strict external collector.

### 2. P1 — Configured outbound policy is bypassed

Location: [route.rs](../../zebra-rs/src/bgp/route.rs:11257), `bgpls_origin_reach`; `route_sync_bgpls`.

The only eligibility check is an established session with the negotiated family. Neither path evaluates the peer's link-state outbound policy before sending. The configuration callbacks accept per-family `afi-safi ... policy out` bindings, but these emitters do not consult the policy slots. Even an unconditional deny policy therefore fails to suppress the topology feed, and attribute-setting actions are ignored.

Evaluate a BGP-LS-capable outbound policy in both paths. Node/link objects need an appropriate policy context rather than an invented IP prefix. Track advertised objects per peer so policy changes can withdraw previously accepted objects. Verify a deny-all binding before establishment and a permit-to-deny edit while established. Prefix-based BGP-LS matching can be a separate extension, but an accepted unconditional deny must not silently have no effect.

### 3. P2 — Route Refresh does not replay BGP-LS objects

Location: [peer.rs](../../zebra-rs/src/bgp/peer.rs:2148), `FsmEffect::RouteRefreshRecv`; [route.rs](../../zebra-rs/src/bgp/route.rs:6945), `route_soft_out_peer`.

Route Refresh dispatches to `route_soft_out_peer`, which handles IPv4/IPv6 unicast, VPNv4/VPNv6, and EVPN only. The new `route_sync_bgpls` is called at establishment, but never on refresh. A collector requesting AFI 16388 / SAFI 71 replay after changing its receive policy gets no topology until an IGP delta occurs or the BGP session reconnects. An unchanged topology can therefore remain missing indefinitely after a receive-policy change.

Add family-aware replay of the eligible local BGP-LS objects on Route Refresh and operator soft-out, using the same egress policy/attribute preparation as initial synchronization. Verify refresh with a populated but unchanged producer LSDB.

### 4. P2 — UPDATE serialization can exceed the negotiated message limit

Location: [update.rs](../../crates/bgp-packet/src/update.rs:410), `pop_bgpls`; `pop_bgpls_withdraw` has the same unchecked emission pattern.

The builders construct `FixedBuf` with `max_packet_size`, then emit attributes and NLRIs through `get_mut()`. That exposes a growable `BytesMut` and bypasses capacity enforcement. Neither builder checks final size before narrowing lengths to `u16` and returning the packet. An oversized BGP-LS Attribute or NLRI batch therefore produces a message the peer is not allowed to receive, potentially resetting the feed session.

A temporary Rust probe linked against the actual `bgp-packet` library used one Node NLRI and a 5000-byte opaque BGP-LS TLV with `UpdatePacket::with_max_packet_size(4096)`. `pop_bgpls()` returned a 5084-byte UPDATE with header length 5084. The probe also confirmed the originated attribute defaults: zero AS_PATH segments and no LOCAL_PREF. The probe lived in a temporary directory and was removed after execution. This synthetic size case establishes a builder defect; it does not show that the current small IS-IS topology naturally reaches that size.

Enforce negotiated limits and implement the required oversize handling rather than returning an invalid packet. Batch splitting only helps multiple NLRIs; an individually oversized attribute needs separate handling. [RFC9552 section 5.3](https://www.rfc-editor.org/rfc/rfc9552.html#section-5.3) discusses maximum-message-size handling. Verify ordinary and extended-message limits and ensure a rejected or split batch is not silently drained.

## Current feed functionality and coverage

The previous status that transmission to external peers is wholly unimplemented is now superseded for locally originated objects. The producer sends topology deltas, BGP stores them in its local RIB, and the new emitters serialize MP_REACH/MP_UNREACH for AFI 16388 / SAFI 71. Type 29 is now emitted alongside reachable objects. Establishment dumps selected originated objects so an already-converged IGP can feed a late peer.

Received BGP-LS objects still stop at the local RIB; propagation/reflection is deliberately unimplemented. The current producer is IS-IS, not OSPF. Local origination represents the producer's entire eligible LSDB view, including remote IGP objects, rather than only this router's physical links.

The new collector runs no IGP and learns from one iBGP producer, making its RIB useful evidence of BGP-wire delivery when the BDD is executed. Its assertions cover node/link presence, both directed delays, and top-level performance values. The `+2 more` assertion counts extra TLVs; it does not decode TLV 1122's nested metrics or application masks. The BGP-LS attribute codec stores TLV values opaquely, so claims that the collector validates ASLA internals overstate this coverage.

The BDD has no explicit topology withdrawal, attribute-change, reconnect, Route Refresh, export-policy, external-AS, or packet-limit scenario. Initial convergence and advertisement also overlap, so it does not explicitly force the late-peer condition even though the commit reports mutation testing of the establishment dump.

## Validation

- `cargo test -p zebra-rs --bin zebra-rs bgp_ls`: 23 passed; producer, translation, and display tests.
- `cargo test -p bgp-packet bgpls`: 20 passed; attribute/NLRI codec tests.
- Temporary serialization probe: reproduced a 5084-byte UPDATE under a 4096-byte limit.
- BDD was inspected, not run during this review. The commit's reported live and mutation-test results were not independently reproduced here.

These passing tests do not cover the new emitters' peer-specific feed behavior. Delivery to a strict external-AS controller remains unverified and is affected by finding 1.
