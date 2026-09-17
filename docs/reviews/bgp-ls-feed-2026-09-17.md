# BGP-LS feed review

## Resolution — third round

Both findings are fixed.

**Ignored match conditions.** `entry_matches_bgpls` checked nine clauses
and silently ignored five — `match_next_hop`, `match_as_path_len`,
`match_as_path_len_uniq`, `match_weight`, `match_color` — plus a nested
`call`. An entry carrying only one of those therefore matched every
object, so `match as-path-len ge 100 deny` became a table-wide deny.
That is precisely the failure the function's own comment warned about
for `match prefix-set`, written while the same bug sat five lines below
it.

The evaluator now destructures `PolicyEntry` field by field with no
`..`, so adding a clause to the struct breaks this build rather than
silently widening a conditional rule into an unconditional one. The
evaluatable clauses are evaluated; the ones needing context this family
has no NLRI for — a prefix set, an IPv4 next hop, the EVPN
discriminators, a non-zero tag, a nested call — fail the entry.

**LOCAL_PREF toward an external peer.** `bgpls_egress_attr` only added
LOCAL_PREF for iBGP, but policy runs afterwards and `set
local-preference` does not know the peer type, so a policy-set value
reached eBGP UPDATEs. The final attribute is now produced in one place,
`bgpls_out_attr` — egress transform, then policy, then the rules that
hold regardless of what policy asked for — and the strip lives there,
after every writer.

Gates: a BDD scenario where entry 10 denies only paths of length 100 or
more and entry 20 permits, so the feed survives only if the condition is
actually read (mutation-tested by ignoring the clause again); and unit
tests for the strip in both directions, since `show bgp link-state`
renders BGP-LS TLVs and not path attributes, so the collector cannot
observe LOCAL_PREF at all.

## Current re-review: `8731c610`

Reviewed `8731c610` on 2026-09-17. R1 is fixed: per-peer advertised objects are tracked and newly denied objects are withdrawn during delta handling or reconciliation. R3 is fixed for an oversized attribute replacement whose NLRI still fits in a withdrawal: the previous copy is withdrawn. R2 is partially fixed: common attribute matches and several set actions now run, but the matcher silently ignores other accepted conditions, and final session-specific attribute sanitation is missing. Implementation source was not changed.

### R4. P1 — Several configured match conditions become unconditional

Location: [route.rs](../../zebra-rs/src/bgp/route.rs:11363), `entry_matches_bgpls`.

The matcher checks prefix/EVPN context, tag, community/AS-path sets, MED, LOCAL_PREF, and ORIGIN, but never checks `match_as_path_len`, `match_as_path_len_uniq`, `match_weight`, `match_color`, or `match_next_hop`. It falls through to `true` even when one of these conditions is configured and false. This differs from the previous implementation, which rejected conditional entries, and can now allow objects a policy was intended to reject.

Reproduction: bind a policy whose first entry permits only AS-path length 99 and whose next entry denies unconditionally. An ordinary originated feed path has length 0 toward iBGP or 1 toward eBGP, but the first entry still matches and the topology is exported. Reversing the actions makes a conditional deny suppress the entire feed. Color can be available after a preceding policy action; lack of a prefix does not justify ignoring these conditions.

Evaluate every accepted attribute condition, with explicit defaults/context for weight and the MP_REACH next hop. If a condition cannot be supported, fail the entry or reject its configuration rather than treating it as absent. Add negative-condition tests, especially an impossible AS-path length followed by deny-all, and verify both initial and delta feeds.

### R5. P2 — Policy-set LOCAL_PREF leaks into external UPDATEs

Location: [route.rs](../../zebra-rs/src/bgp/route.rs:11308), `policy_list_apply_bgpls`; callers apply `bgpls_egress_attr` before policy evaluation.

An unconditional permit with a LOCAL_PREF set action adds the attribute even for an external peer. The policy result goes straight to `bgpls_send_reach`, whose serializer emits LOCAL_PREF whenever present. No final egress step removes it. Reproduction: apply an unconditional permit with LOCAL_PREF 200 to the external collector's link-state family; announcements contain path attribute type 5 despite the external session.

[RFC4271 section 5.1.5](https://www.rfc-editor.org/rfc/rfc4271.html#section-5.1.5) prohibits LOCAL_PREF in external UPDATEs except for confederations. Sanitize the final post-policy attribute for the session before serialization. Verify that the policy value appears for iBGP and is absent for ordinary eBGP, in both initial synchronization and delta handling.

### Validation and limits

- `cargo test -p zebra-rs --bin zebra-rs bgp_ls`: 23 passed.
- `cargo test -p bgp-packet bgpls`: 20 passed.
- `git diff --check 9014602a HEAD`: passed.
- BDD scenarios for deny withdrawal and restoration were inspected, not run during this review. Their reported mutation-test result was not independently reproduced.

No direct feed-policy evaluator tests were added in this commit. The passing tests cover producer/translation/display and packet codecs, rather than R4/R5. The new evaluator also leaves some accepted set actions unsupported, including `set color`, and its next-hop action does not update MP_REACH. The resolution notes' claim that every set action applies should be narrowed accordingly. Live refresh, attribute-policy, oversized-replacement, and reconnect coverage remain incomplete.

## Implementation author's resolution — second round


R1, R2 and R3 are fixed. All three came back to the same absence: there
was no Adj-RIB-Out for BGP-LS, so nothing knew what a peer currently
held and every correction had to be phrased as "don't send it again".

| # | Finding | Fix |
|---|---|---|
| R1 | Permit-to-deny never withdrew | `peer.adj_out.bgp_ls` is now populated on every send and drained on every withdraw; `route_sync_bgpls` reconciles held-against-eligible and withdraws the difference |
| R2 | Permit ignored match and set actions | `policy_list_apply_bgpls` / `entry_matches_bgpls`, modelled on the EVPN pair: the common attribute matches and every set action apply |
| R3 | Oversized replacement left stale state | An oversized object whose NLRI the peer already holds is withdrawn, so the collector cannot keep a copy that can never be corrected |

The correction R1 makes to the previous resolution note is accepted: I
wrote that a permit-to-deny edit "takes effect on the next refresh or
delta", and for an object already sent that was simply wrong — a refresh
re-sent the permitted set and said nothing about the rest.

On R2's scope: the matcher takes the common BGP attribute clauses
(communities, ext/large communities, AS-path set, MED, LOCAL_PREF,
ORIGIN) and rejects the entry for anything needing context this family
does not have — a prefix set, the EVPN discriminators, a non-zero tag.
Those fail the entry rather than being skipped, because skipping is what
turns `match prefix-set X deny` into a table-wide deny; the EVPN matcher
documents the same trap for `match tag`. A descriptor-specific matcher
remains a separate feature.

The `adj_out` entries exist to answer "does the peer hold this", so they
carry the advertised attribute and no path-selection state.

Gated by two new scenarios: an unconditional deny bound while the
collector already holds the topology must empty its RIB, and removing
the binding must restore it — on a stable LSDB, with no session reset.
Mutation-tested: dropping the reconcile's withdraw loop fails the deny
scenario.

Not addressed: a wire-visible set action and an attribute-only match
have unit-level support but no BDD scenario, and the small-to-oversized
transition is exercised only by the reviewer's probe, since the BDD
topology produces nothing near the limit.

## Previous re-review: `9014602a`

Reviewed `9014602a` on 2026-09-17. Peer-specific AS_PATH/LOCAL_PREF construction and Route Refresh replay are implemented in both advertisement paths. Oversized UPDATEs are no longer returned to the sender. Outbound filtering is partially implemented; three functional findings remain below. Implementation source was not changed. The original review and implementation author's resolution notes are retained below as history.

### R1. P1 — Permit-to-deny changes never withdraw the existing feed

Location: [route.rs](../../zebra-rs/src/bgp/route.rs), `bgpls_origin_reach` and `route_sync_bgpls`, their `bgpls_policy_out` rejection branches.

Both paths simply continue when the policy denies. There is no per-peer advertised-object tracking or withdrawal for an object that previously passed. Reproduction: allow an initial topology dump, attach an unconditional deny-all outbound policy, and request soft-out or Route Refresh. Every object is skipped, but the collector receives no MP_UNREACH and keeps the previously advertised topology. Subsequent denied IGP attribute deltas also do not remove it. Only a real producer withdrawal or session teardown removes that copy.

The resolution note's statement that a permit-to-deny edit takes effect on the next refresh or delta is therefore incorrect for objects already sent. Track accepted objects per peer and reconcile the previously advertised set against the currently eligible set, sending withdrawals for newly denied objects. Verify permit-to-deny and deny-to-permit edits on a stable LSDB without resetting the session.

### R2. P2 — An unconditional permit ignores its attribute actions

Location: [route.rs](../../zebra-rs/src/bgp/route.rs), `bgpls_policy_out`, `PolicyAction::Permit => Some(attr)`.

The evaluator returns the attribute unchanged rather than applying the policy entry's set actions. An unconditional permit with `set origin`, MED, communities, or AS-path prepend therefore permits the feed but does not perform the configured transformation. This is independent of Link-State descriptor matching: the function already has a BGP attribute context and `bgpls_egress_attr` has already populated ORIGIN/AS_PATH and internal LOCAL_PREF.

Likewise, ordinary attribute match clauses such as `match origin igp` or AS-path length are skipped merely because they are conditional, even though the required data is available. A descriptor-specific matcher can remain a separate feature, but absent IP-prefix context does not make BGP path attributes unavailable. Apply supported attribute match/set behavior and explicitly reject unsupported policy forms rather than silently accepting misleading configuration. Verify an unconditional permit with a wire-visible set action and an attribute-only match, in both delta and synchronization paths.

### R3. P2 — An oversized replacement leaves stale attributes on the collector

Location: [update.rs](../../crates/bgp-packet/src/update.rs), `pop_bgpls`, the `oversize` return; [route.rs](../../zebra-rs/src/bgp/route.rs), callers that send only when serialization returns `Some`.

The size guard prevents illegal framing, but silently drops and drains the reachable object. If the same NLRI was previously advertised with a smaller attribute, an oversized replacement sends neither updated reachability nor a withdrawal. The collector keeps its obsolete metric/attribute view while the producer's local RIB contains the new view. The IGP producer's diff has already advanced after delivering the delta to BGP, so an unchanged LSDB will not retry it. Refresh attempts also drop the oversized replacement and leave the old copy intact.

A temporary probe linked to the actual packet library emitted a small Node advertisement, then supplied the same NLRI with a 5000-byte BGP-LS TLV under a 4096-byte limit. The replacement returned `None` and its NLRI queue was empty; no withdrawal was generated. This establishes builder behavior, with stale remote state inferred from the checked caller paths. The synthetic object is larger than those in the current small BDD topology.

Return a distinct serialization error and reconcile previously advertised state. Choose a size-safe advertisement strategy or withdraw an unsendable object that was previously sent, so the collector cannot retain the old values indefinitely. [RFC9552 section 5.3](https://www.rfc-editor.org/rfc/rfc9552.html#section-5.3) permits producer mitigation mechanisms; silently retaining obsolete remote state does not establish an accurate feed. Verify small-to-oversized-to-small transitions without a session reset.

### Re-review validation

- `cargo test -p zebra-rs --bin zebra-rs bgp_ls`: 23 passed.
- `cargo test -p bgp-packet bgpls`: 20 passed.
- Temporary probe: small advertisement serialized; oversized replacement returned `None` and drained the NLRI.
- `git diff --check 09b6fc6f HEAD`: passed.
- BDD was inspected, not run during this re-review. The collector now uses external AS 65072 with first-AS enforcement; the commit's reported mutation-test result was not independently reproduced here.

## Original review: `09b6fc6f`

Reviewed `09b6fc6fc5b5a5a39c8fcc19f3b2c6e15c1be995` on 2026-09-17. Scope: IS-IS producer delivery, local origination, initial synchronization, per-peer UPDATE construction, receive/withdraw handling, and collector coverage. Implementation source was not changed.

## Resolution

Implementation author's resolution notes for `9014602a` follow. The current re-review above supersedes the claim that all four findings are fully resolved.

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
