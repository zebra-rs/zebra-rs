# BGP-LS TE performance export review

Status update (2026-09-17): `09b6fc6f` implements outbound advertisement and establishment synchronization for locally originated BGP-LS objects. The older transmission limitation below is historical. Peer-specific attribute, policy, refresh, and size-limit findings are recorded in the [BGP-LS feed review](bgp-ls-feed-2026-09-17.md). Strict external-controller delivery and ASLA internals remain unverified by this review.

Reviewed commit `06c19727009c5134705c1347de64fe2592bafa69` on 2026-09-16. Scope includes the IS-IS performance-metric export, new accessors, BGP-LS display, and the accompanying Flex-Algo receive change. Implementation source was not changed.

## Current review: `68851ee7` and `224a49cb`

Reviewed the zero-mask fix in `68851ee7` and the new BDD topology in `224a49cb`. R4 is fixed. No new functional findings were identified in these changes.

The exporter now distinguishes originally empty masks from masks emptied by removing RSVP-TE. Both zero-mask export paths have regression tests, and RSVP-TE-only export remains top-level only.

The BDD feature correctly expects both routers to hold both directed links from their complete LSDBs. Neighbor-specific delay assertions exercise remote IS-IS encoding/decoding followed by local BGP-LS translation. The `+2 more` assertion checks only the additional TLV count; it does not decode TLV 1122 or verify its masks.

Validation during this review:

- `cargo test -p zebra-rs --bin zebra-rs bgp_ls`: 23 passed, including both zero-mask regressions.
- `cargo test -p zebra-rs --bin zebra-rs peer_min_delay`: 12 passed.
- `cargo test -p bgp-packet bgpls_attr`: 10 passed.
- `git diff --check HEAD~2 HEAD`: passed.

The new BDD topology/configs were inspected but not run during this review. BGP-LS transmission to external peers remains unimplemented in [`route_bgpls_originate`](../../zebra-rs/src/bgp/route.rs), which stores locally originated routes in the local RIB and defers re-advertisement. Controller delivery is still unverified. Completing that validation requires implementing outbound BGP-LS advertisement, receiving BGP UPDATEs on an external peer, and decoding the performance attributes and TLV 1122 application masks. Implementation source was not changed.

## Resolution

All six findings are fixed on branch `bgp-ls-te-perf-tlvs`. The review
rounds below are kept as written, as the record of what was found.

| # | Finding | Fixed in | Gate |
|---|---|---|---|
| 1 | ASLA metrics flattened into top-level TLVs | `9d85333e` | `asla_scoped_metrics_go_to_tlv_1122_not_top_level`, `two_aslas_keep_their_own_values` |
| 2 | Flex-Algo inline fallback bypassed ASLA/L-flag | `9d85333e` | `peer_min_delay_*` (9 cases) |
| R1 | IS-IS mask lengths copied into an illegal BGP-LS encoding | `d7ad9e4c` | `asla_masks_widen_to_a_bgp_ls_legal_length`, `asla_widens_the_user_defined_mask_independently` |
| R2 | Translation ignored the IS-IS L-flag | `d7ad9e4c` | `l_set_asla_carries_the_legacy_value_into_tlv_1122`, `l_set_asla_ignores_its_own_nested_values` |
| R3 | Flex-Algo read only the first applicable ASLA | `d7ad9e4c` | `peer_min_delay_searches_every_applicable_asla`, `..._every_zero_mask_asla`, `..._treats_a_split_l_flag_as_set` |
| R4 | Zero-length-mask ASLAs dropped on export | `68851ee7` | `zero_length_mask_asla_is_preserved_in_tlv_1122`, `..._with_l_flag_carries_the_legacy_value` |

Every fix was mutation-tested: each gate was confirmed to fail with its
fix reverted.

Two notes where the fix differs from the suggestion:

- **1 and R2 interacted.** Reading RFC 9294 §4 for R2 also corrected the
  fix for 1. Rule 2(B) puts RSVP-TE attributes in the top-level TLVs
  "rather than the ASLA TLV"; `9d85333e` had emitted both, reading §2
  and §3 as cumulative. An RSVP-TE-only ASLA now produces no ASLA TLV,
  and a mixed R+X ASLA has the RSVP-TE bit stripped from the scoped
  copy's mask.
- **R4 was self-inflicted by R2's fix.** The RSVP-TE strip introduced a
  guard asking whether stripping had emptied the mask, answered with
  `all(|b| *b == 0)` — vacuously true of a mask that was empty already.
  The two cases are now separated by whether the mask selected anything
  before the strip.

### On the "no live validation" caveat

Every round closed by noting that nothing had been validated against a
live peer, and that was the right thing to keep saying: four rounds of
spec violations were found in code whose only check was its author's
reading of a diagram.

`224a49cb` adds `bdd/tests/features/bgp_ls_te_metric.feature`, the first
BGP-LS topology in the repo. Because the producer walks the whole LSDB
rather than just the self-originated part, it is a real round trip for
the IS-IS half: one router encodes the RFC 8570 sub-TLVs, the other
parses them off the wire, and the second router's producer translates
what it parsed. Each asserts it sees the *other's* delay.

What that still does not reach is the BGP wire. BGP-LS re-advertisement
to peers is not implemented — `route_bgpls_originate` records
"Re-advertisement to peers is deferred", and `adj_out.bgp_ls` is only
ever cleared — so no BGP-LS Attribute enters an UPDATE, and the ASLA TLV
(1122) internals rest on unit tests. Closing that needs either a BGP-LS
ASLA parser to decode what we encode, or the egress path and a real
peer. Both are separate features.

## Latest review: `d7ad9e4c`

Reviewed `d7ad9e4ce0110f4fa146dfade14473ee39d0a096`. R1, R2, and R3 from the preceding re-review are fixed for their stated reproduction cases: masks widen to valid BGP-LS widths, L-set ASLAs source legacy performance metrics, and the Flex-Algo reader searches all applicable containers. One new P1 export finding remains.

### R4. P1 — Zero-length-mask ASLA metrics are dropped

Location: [bgp_ls.rs](../../zebra-rs/src/isis/bgp_ls.rs), `push_te_performance`, the all-zero-mask check following `sabm_without_rsvp_te`.

The exporter skips an ASLA whenever the remaining SABM and UDABM contain no set bits. Both `all` checks also return true for empty slices. Consequently, an original ASLA with both masks empty, L clear, and nested min/max delay of 700 us yields no performance metric at all: there is no inline metric, the RSVP-TE branch does not run, and the ASLA branch skips it.

A zero-length application mask is a valid any-application advertisement, not an RSVP-TE-only advertisement. [RFC9294 section 4, rule (2)(e)](https://www.rfc-editor.org/rfc/rfc9294.html#section-4) explicitly requires exporting its attributes in a BGP-LS ASLA with a zero-length mask. The Flex-Algo reader now correctly accepts such input, making the loss in the BGP-LS translation particularly visible: local SPF sees the metric while the controller does not.

Distinguish an original zero-length-mask ASLA from a scoped ASLA whose only application was RSVP-TE. Preserve the former as TLV 1122 with zero SABM/UDABM lengths. Skip the latter after extracting its RSVP-TE attributes to top level. Add a BGP-LS regression for an L-clear zero-mask ASLA containing delay/loss, including a case with no inline copy. Existing zero-mask tests exercise the Flex-Algo reader, not the export path.

### Latest validation

- `cargo test -p zebra-rs --bin zebra-rs bgp_ls`: 21 passed.
- `cargo test -p zebra-rs --bin zebra-rs peer_min_delay`: 12 passed.
- `cargo test -p bgp-packet bgpls_attr`: 10 passed.
- `git diff --check HEAD~1 HEAD`: passed.

R4 was identified by source tracing; a new corrective regression was not added or executed. No live controller/BDD validation was run. Implementation source remains unchanged.

## Re-review of `9d85333e`

Reviewed `9d85333e18203c7ec94c5b10faaeb1ab1b482011`. The unconditional Flex-Algo inline fallback is removed. BGP-LS now separates inline metrics from nested ASLA metrics and preserves distinct scoped values through TLV 1122. The original scoping finding is partially resolved; the following translation and selection gaps remain.

### R1. P1 — IS-IS mask lengths are copied into an incompatible BGP-LS encoding

Location: [bgpls_attr.rs](../../crates/bgp-packet/src/attrs/bgpls_attr.rs), `bgpls_asla_value`, lines 105–111.

The helper emits the input mask lengths and bytes unchanged. IS-IS permits mask lengths from 0 through 8 and recommends the shortest necessary encoding. BGP-LS ASLA uses OSPF-style lengths, limited to 0, 4, or 8. Consequently, the normal one-byte X-mask `[0x10]` produces a BGP-LS ASLA with SABM length 1, rather than length 4 with mask `[0x10, 0, 0, 0]`. This affects this daemon's own one-byte masks as well as common peer encodings; compliant consumers cannot use the resulting ASLA encoding.

See [RFC9294 section 2](https://www.rfc-editor.org/rfc/rfc9294.html#section-2), [RFC8920 section 3.1](https://www.rfc-editor.org/rfc/rfc8920.html#section-3.1), and [RFC9479 section 4.1](https://datatracker.ietf.org/doc/html/rfc9479#section-4.1).

Normalize SABM and UDABM independently: preserve length zero, pad lengths 1–4 to four octets, and lengths 5–8 to eight octets, appending zero octets so bit positions remain unchanged. Handle invalid lengths explicitly. The exact-byte ASLA test currently asserts the invalid length-1 output; update it and add coverage for user-defined masks and lengths 0, 1, 4, 5, and 8.

### R2. P1 — BGP-LS translation ignores the IS-IS L-flag

Location: [bgp_ls.rs](../../zebra-rs/src/isis/bgp_ls.rs), `push_te_performance`, lines 190–203.

The exporter always reads `asla.subs`, regardless of `asla.l_flag`, and skips an ASLA if that nested metric list is empty. A valid L-set ASLA is expected to have no nested metrics: the attributes come from inline legacy advertisements. For example, an inline minimum delay of 700 us plus an X-scoped L-set empty ASLA produces only top-level 1115 and no X-scoped TLV 1122. BGP-LS thus loses the indication that Flex-Algo uses that legacy delay. If an L-set ASLA does contain prohibited nested values, the exporter incorrectly uses them instead of ignoring them.

[RFC9294 section 4, rule (2)(a)](https://www.rfc-editor.org/rfc/rfc9294.html#section-4) requires copying legacy attributes into a BGP-LS ASLA for the indicated non-RSVP applications. [RFC9479 section 4.2](https://datatracker.ietf.org/doc/html/rfc9479#section-4.2) requires ignoring nested attributes when L is set.

Choose the source before translation: inline metrics for L-set ASLAs, nested metrics for L-clear ASLAs. Apply the specified application-mask rules, including excluding RSVP-TE from the L-set scoped copy while retaining top-level legacy attributes. Add tests for X/L-set, combined R+X/L-set, and L-set with nested values that must be ignored. The new Flex-Algo L-flag unit test checks the local SPF reader, not this BGP-LS export path.

### R3. P1 — Flex-Algo only reads the first applicable ASLA

Location: [flex_algo.rs](../../zebra-rs/src/isis/flex_algo.rs), `applicable_asla`, lines 102–115, and `peer_min_delay`, lines 89–94.

The selection returns the first X-scoped ASLA as a whole and searches for delay only within it. IS-IS allows multiple ASLAs for a link with non-conflicting application/attribute pairs. A valid entry can therefore put X-scoped affinity in its first L-clear ASLA and X-scoped min/max delay in its second L-clear ASLA. This reader returns `None` and prunes the link; reversing the two ASLAs restores the delay. The same first-container limitation affects multiple zero-mask ASLAs carrying different attributes.

[RFC9479 section 4.2](https://datatracker.ietf.org/doc/html/rfc9479#section-4.2) permits multiple ASLAs and resolves conflicts per application/attribute pair, rather than selecting a single container for all attributes.

Resolve the applicable advertisement set, then look for the requested attribute across that set in advertisement order. Preserve explicit-X precedence over zero-mask scope and the L-flag rules; do not restore the unconditional inline fallback. Add tests with affinity and delay split across two X-scoped ASLAs in both orders, and equivalent zero-mask containers.

### Re-review validation

- `cargo test -p zebra-rs --bin zebra-rs bgp_ls`: 18 passed.
- `cargo test -p zebra-rs --bin zebra-rs peer_min_delay`: 9 passed.
- `cargo test -p bgp-packet bgpls_attr`: 8 passed.
- `git diff --check HEAD~1 HEAD`: passed.

The existing tests do not cover R2 or R3, and the exact-byte test encodes R1's invalid mask length. The findings were source-traced against the RFCs; new corrective regression tests were not executed. No live controller/BDD validation was run, and implementation source was not changed.

## Findings

### 1. P1 — ASLA metrics lose their application scope during BGP-LS export

Location: [crates/isis-packet/src/sub/neigh.rs](../../crates/isis-packet/src/sub/neigh.rs), `link_attr_subs`, lines 211–220; [zebra-rs/src/isis/bgp_ls.rs](../../zebra-rs/src/isis/bgp_ls.rs), `push_te_performance`, starting at line 118.

The accessors search inline attributes first, then flatten every ASLA's nested attributes without inspecting its application masks or L-flag. Export writes whichever matching attribute appears first as a top-level RFC8571 TLV. This changes the meaning of an application-specific metric and discards other applications' distinct values.

For example, an entry with no inline delay and two L-clear ASLAs can carry RSVP-TE minimum delay 900 us and Flex-Algo minimum delay 100 us. If the Flex-Algo ASLA appears first, the exporter emits top-level 1115 with 100 us and drops the RSVP-TE 900-us value. Reordering the same two ASLAs changes the exported metric. An X-only ASLA is likewise exported as a top-level metric, although it was never advertised for RSVP-TE.

[RFC9294 sections 3 and 4](https://www.rfc-editor.org/rfc/rfc9294.html#section-3) require preserving application-specific attributes in BGP-LS ASLA TLV 1122. Legacy inline attributes continue to use the corresponding top-level TLVs; RSVP-TE-scoped ASLA attributes also use top-level encodings under the specified procedures. The existing RFC8571 code points are not an exemption from these application semantics.

Preserve ASLA masks and translate application-specific metrics into TLV 1122, including the applicable L-flag procedures. Keep top-level sourcing separate for legacy and RSVP-TE attributes. If this change intentionally implements only legacy performance export, omit unsupported scoped metrics rather than flattening them. Add tests with distinct RSVP-TE and Flex-Algo metrics in both ASLA orders, X-only ASLA, and inline values that differ from scoped ones. The current `link_attr_reads_performance_from_asla_too` test explicitly expects an X-only ASLA to become top-level 1115 and therefore encodes the problematic behavior.

### 2. P1 — Flex-Algo inline fallback bypasses the required ASLA/L-flag selection

Location: [zebra-rs/src/isis/flex_algo.rs](../../zebra-rs/src/isis/flex_algo.rs), `peer_min_delay`, lines 97–110; used by [graph.rs](../../zebra-rs/src/isis/graph.rs).

When `parse_asla_min_delay` returns no value, `peer_min_delay` unconditionally accepts inline sub-TLV 34. This includes links with no ASLA, links whose ASLA applies only to another application, and an X-scoped L-clear ASLA that intentionally supplies no minimum delay. The fallback treats absence of a usable scoped metric as permission to use the legacy metric.

For example, an X-scoped L-clear ASLA without delay plus an inline RSVP-TE delay of 700 us now gives the Flex-Algo graph a 700-us edge instead of pruning the link for missing Flex-Algo delay. Other routers that enforce the scope can prune the same edge, creating inconsistent delay topologies and possible forwarding failures.

[RFC9350 section 12](https://www.rfc-editor.org/rfc/rfc9350.html#section-12) requires ASLA advertisement for Flex-Algo link attributes. The IS-IS exception is explicitly signaled by the ASLA L-flag; absence of an ASLA is not that signal.

Resolve an applicable ASLA first, considering explicit X scope and valid any-application encodings. For an applicable L-clear ASLA, read its nested metric and return missing if absent. Use inline metrics only when an applicable ASLA's L-flag authorizes legacy sourcing. Add tests for X/L-clear with missing delay, other-application-only ASLA plus inline delay, no-ASLA inline delay, and X/L-set legacy sourcing. The new tests expecting unconditional inline fallback should be revised to reflect these scope rules.

## Validation

- `cargo test -p zebra-rs --bin zebra-rs bgp_ls`: 15 passed, including producer diffs, metric translation, and short-TLV display handling.
- `cargo test -p zebra-rs --bin zebra-rs peer_min_delay`: 4 passed. These tests include expectations for the fallback behavior identified in finding 2.
- `cargo test -p bgp-packet bgpls_attr`: 8 passed, covering generic attribute encoding and preservation.
- `git diff --check HEAD~1 HEAD`: passed.

The RFC8571 TLV codes, lengths, integer layouts, A-bit placement, reserved-octet clearing, and IEEE 754 bandwidth translation match [RFC8571 section 2](https://datatracker.ietf.org/doc/html/rfc8571#section-2). Absent metrics are omitted, and the added display paths check lengths before indexing or slicing.

The findings above are based on source tracing and the RFC selection/translation rules; corrective regression tests were not added or executed. No live BGP-LS controller or BDD topology was run. OSPF BGP-LS export is outside this commit's scope.
