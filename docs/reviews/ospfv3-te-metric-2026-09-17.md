# OSPFv3 IGP TE metric review

## Resolution

All six findings are fixed on branch `ospfv3-te-metric`; the review
rounds below are kept as written, as the record of what was found.

| # | Finding | Fixed in | Gate |
|---|---|---|---|
| 1 | Local metric changes scheduled no SPF | `be0676ae`, corrected in `be0a650d` and `7b8bc851` | `spf_schedule_area` at both TE-carrying originators, originate and flush |
| 2 | Zero-mask delay ASLAs rejected | `be0676ae`, completed in `f7d774ae` | `asla_min_delay_*` selection tests |
| 3 | Peer renumber stranded STAMP | `be0676ae` | `stamp_reconcile_and_originate` in `NbrSourceChanged` |
| R1 | Generic delay borrowed despite an explicit ASLA | `f7d774ae` | `explicit_advertisement_without_delay_still_excludes_the_generic_one` |
| R2 | Affinity ignored zero-mask ASLAs | `f7d774ae` | `affinity_and_delay_use_the_same_applicable_set` |
| R3 | Invalid mask lengths accepted | `7b8bc851` | `invalid_mask_lengths_*`, `an_invalid_asla_does_not_suppress_a_valid_generic_one` |

Plus the OSPFv2 withdrawal scheduling, which `f7d774ae` put in
`router_info_lsa_originate` and `7b8bc851` moved to
`ext_link_lsa_originate`, where a link's delay is actually withdrawn.

Every fix was mutation-tested: each gate was confirmed to fail with its
fix reverted.

### What the rounds say about the process

Three defects in this branch came from a text-anchored edit landing in a
neighbouring function: the `fn len` splice (caught by the compiler), the
SPF schedule reaching `ext_intra_area_prefix_v3_lsa_originate` (caught
by listing call sites), and the OSPFv2 flush schedule landing in
`router_info_lsa_originate` (caught only by review — it compiled and
passed the whole suite). The last two were the same call, and the second
happened while fixing the first. All four `spf_schedule_area` sites now
have their owning function asserted.

R1 has a different shape and is worth recording separately. The IS-IS
implementation of the same RFC 9492 §5 rule, in
`isis::flex_algo::applicable_aslas`, is correct: it selects the
applicable set first and searches it afterwards. Porting the rule to
OSPF, it was re-derived from memory as a single expression,
`specific.or(any_application)`, which collapses those two steps and
answers a different question — whether an explicit advertisement
supplied the attribute, rather than whether one exists. The correct
version was in this repository the whole time.

### Still not covered

No BDD exercises delay-based path switching, endpoint renumbering, or
malformed-packet receive handling; those rest on selector unit tests
built from constructed ASLAs. The two topologies here cover origination,
measurement, and the static-over-measured merge. Interop against another
implementation is untested, and the SR origination gate, static-only
loss and absent bandwidth variants remain implementation limits.

## Current re-review: `7b8bc851`

Reviewed `7b8bc851` on 2026-09-17. R3 is fixed for the reported selection cases: both application-mask lengths are checked against 0/4/8 before an ASLA can enter the explicit or generic set. This guard is shared by delay and affinity consumers on both OSPF versions. The related OSPFv2 withdrawal scheduling call is now in the Extended-Link Opaque LSA flush branch, and the misplaced Router Information call was removed. No new functional findings were identified in this patch. Implementation source was not changed.

All previously reported OSPFv3 findings are resolved for their stated reproduction cases. The new tests cover invalid SABM and UDABM independently, legal eight-octet masks, invalid explicit affinity coexisting with valid generic delay in either order, and the OSPFv2 guard. These are selector tests using constructed ASLAs; they do not establish end-to-end malformed-packet handling.

Validation:

- `cargo test -p zebra-rs --bin zebra-rs ospf::`: 119 passed.
- `cargo test -p ospf-packet ospfv3_asla`: 3 passed.
- `git diff --check f7d774ae HEAD`: passed.
- BDD was not run. Live delay-based path switching and STAMP endpoint renumbering remain unverified by this review.

The SR origination gate, static-only loss support, and absent bandwidth metric variants remain implementation limits rather than new findings. Historical review sections below retain the issues as originally reported.

## Previous re-review: `f7d774ae`

Repeat review on 2026-09-17: HEAD remains `f7d774ae`, with no implementation changes since the preceding review. Rechecked application-mask decoding/selection and both versions' withdrawal scheduling. R3 and the related OSPFv2 scheduling issue remain open; no additional findings were identified. Tests were not rerun against the unchanged implementation; the results below are from the preceding review. Only this review document was updated.

Reviewed `f7d774ae` on 2026-09-17. R1 and R2 are fixed for their stated cases. The shared selector now chooses explicit advertisements by presence, searches that set for each attribute, and uses zero-mask advertisements only when no explicit set exists. Both affinity LSDB walkers use this selector. Three new regression tests cover explicit affinity without delay, delay split across explicit advertisements, and consistent affinity/delay selection. Implementation source was not changed.

### R3. P2 — Invalid application-mask lengths still affect the topology

Location: [flex_algo.rs](../../zebra-rs/src/ospf/flex_algo.rs:219), `asla_readers`; [v3.rs](../../crates/ospf-packet/src/v3.rs:2454), `Ospfv3AslaSubTlv::parse_be`.

Neither decoding nor the shared selector validates SABM/UDABM lengths. The codec accepts any length that fits in the enclosing value, and `is_flex_algo` checks only the first SABM octet. An ASLA with one-octet SABM `[OSPFV3_SABM_FLEX_ALGO]`, empty UDABM, and delay is therefore used as explicit Flex-Algo input. An invalid one-octet ASLA containing only affinity also suppresses an otherwise valid zero-mask delay advertisement under the new presence-based selection, pruning the edge.

[RFC9492 section 5](https://www.rfc-editor.org/rfc/rfc9492.html#section-5) requires ignoring an ASLA when either application-mask length is outside 0, 4, or 8. Filter invalid containers before deciding whether an explicit application advertisement exists, and ensure the surrounding LSA and valid sibling attributes remain usable. Add tests for invalid SABM and UDABM independently, including invalid explicit affinity plus valid generic delay. This decoding gap predates this commit; the shared selector still lacks the required guard and now lets such containers suppress generic attributes as well.

### Related OSPFv2 fix — withdrawal scheduling remains misplaced

Location: [inst.rs](../../zebra-rs/src/ospf/inst.rs:3270), `router_info_lsa_originate`; `ext_link_lsa_originate` flush path around line 3440.

The newly added withdrawal-SPF call is in the Router Information LSA flush branch. That LSA contains capability/FAD information, not link delay. The Extended-Link Opaque LSA flush branch still only floods and never schedules SPF. The previously noted OSPFv2 limitation is therefore not fixed by this commit, although OSPFv3's E-Router-LSA flush scheduling remains correct. Move or add the scheduling call at the TE-carrying flush path and verify it directly; a Router Information flush cannot cover a link-specific withdrawal while SR remains enabled.

### Validation

- `cargo test -p zebra-rs --bin zebra-rs ospf::`: 116 passed.
- `cargo test -p ospf-packet ospfv3_asla`: 3 passed.
- `git diff --check be0a650d HEAD`: passed.
- BDD was not run. Live path switching, renumbering, and invalid-mask receive handling remain unverified by these tests.

## Previous re-review: `be0a650d`

Reviewed fixes in `be0676ae`, the static-metric BDD addition in `c8f36471`, and the origination-scheduling correction in `be0a650d` on 2026-09-17. Implementation source was not changed. The original findings below are retained as the historical record.

| Original finding | Current status |
|---|---|
| 1. Local metric changes do not schedule SPF | Fixed for OSPFv3: E-Router-LSA origination and flush schedule the area's throttled SPF |
| 2. Zero-mask delay ASLAs rejected | Partially fixed: ordinary fallback and explicit-delay precedence work; R1 below remains |
| 3. Peer renumber strands STAMP | Fixed: `NbrSourceChanged` calls `stamp_reconcile_and_originate` |

### R1. P1 — Generic delay is used despite an explicit Flex-Algo advertisement

Location: [flex_algo.rs](../../zebra-rs/src/ospf/flex_algo.rs:211), `asla_min_delay` macro, especially `specific.or(any_application)`.

The helper tracks whether an explicit ASLA supplies a delay, rather than whether a matching explicit application advertisement exists. For a Router-Link containing an X-bit ASLA with only Extended Admin Group and a zero-mask ASLA with Min/Max Link Delay of 1100/1200 us, `specific` remains `None` and the helper returns the generic 1100 us delay in either order. The delay graph consequently admits this link.

[RFC9492 section 5](https://www.rfc-editor.org/rfc/rfc9492.html#section-5) prohibits use of zero-mask link attributes when a matching non-zero-mask application advertisement is present. The application selection must therefore be separate from extracting the requested attribute. An explicit Flex-Algo advertisement with no delay leaves delay unavailable; it does not permit borrowing the generic delay. This affects both versions because the macro generates the OSPFv2 and OSPFv3 helpers.

Track the presence of a matching explicit advertisement independently, search all such advertisements for delay, and use zero-mask attributes only if none exists. Add regression cases with an explicit affinity-only ASLA plus generic delay in both orders, and a later explicit ASLA that actually supplies delay. The five added selection tests all put a delay in the explicit ASLA, so they miss this case.

### R2. P2 — Affinity selection still rejects zero-mask attributes

Location: [inst.rs](../../zebra-rs/src/ospf/inst.rs:14595), `flex_algo_link_affinity_v3`.

This is a pre-existing limitation noted in the first review, left unchanged by the delay-reader fix. The affinity reader still filters exclusively on `asla.is_flex_algo()`. A peer's zero-mask ASLA carrying both min/max delay and Extended Admin Group now provides a usable delay but no usable affinity. An include-any/include-all constraint can reject a matching link; an exclude constraint can admit a link whose excluded color was advertised. The delay and affinity consumers therefore disagree about the same ASLA's applicability.

Apply the same RFC9492 application-selection rule to affinity, preserving explicit-application precedence. Verify zero-mask delay and color together under include and exclude constraints. Until then, accepting generic delay alone does not establish interoperability for constrained delay-based Flex-Algo topologies.

### Re-review validation

- `cargo test -p zebra-rs --bin zebra-rs ospf::`: 113 passed, including the five new selection tests.
- `cargo test -p ospf-packet ospfv3_asla`: 3 passed.
- BDD features/configuration were inspected, not executed during this re-review. Neither added topology exercises live delay-based path switching, endpoint renumbering, or the remaining ASLA selection cases.

The SR requirement comment and zero-bound display assertion in the IPv6 feature are corrected. The static feature's claim that average delay is unpinned remains inaccurate: its configuration pins average as well as both bounds. The OSPFv2 originator also still lacks SPF scheduling on its flush path, despite the fix commit's claim that both versions schedule withdrawal; this is outside the OSPFv3 findings above.

## Original review: `8f9e4443`

Reviewed `9c3e5c3d` and `8f9e4443` at HEAD `8f9e4443c60d4aa4ed28d0436723c1c930109c03` on 2026-09-17. Scope: configuration, ASLA codec/origination, IPv6 STAMP lifecycle, delay-based Flex-Algo graph construction, and BDD coverage. The working-tree display changes and static-metric BDD files were also inspected. Existing edits were preserved; implementation source was not changed.

## Findings

### 1. P1 — Local metric changes do not schedule delay-based SPF

Location: [inst.rs](../../zebra-rs/src/ospf/inst.rs), `e_router_v3_lsa_originate`, around lines 11397–11402; callers `process_stamp_event` and `config_ospfv3_interface_te_metric`.

The originator installs the new E-Router-LSA and floods it, but does not schedule SPF. Neither `Lsdb::install_originated` nor `flood_self_originated_lsa` schedules it. The static configuration callback and STAMP event callback only call this originator. Received area LSAs do schedule SPF in `packet_v3.rs`, so peers can recalculate while the advertising router keeps using its old local edge costs.

Reproduction: in a stable delay-based Flex-Algo topology with two alternative paths, change only the source router's outgoing static min/max delay until the preferred path should switch. Its LSDB changes, but no SPF is requested by that operation. A measured delay change or measurement withdrawal has the same missing trigger. Independent peer updates can mask the defect, but cannot guarantee recalculation.

Schedule the area's throttled SPF after a local ASLA change or withdrawal. Verify a local-only delay change switches the installed path, and withdrawing the only measured delay removes the edge without requiring another LSA update.

### 2. P1 — Valid zero-mask ASLAs are rejected by the delay reader

Location: [inst.rs](../../zebra-rs/src/ospf/inst.rs:14607), `flex_algo_link_delay_v3`; [v3.rs](../../crates/ospf-packet/src/v3.rs:2475), `Ospfv3AslaSubTlv::is_flex_algo`.

The new reader requires `asla.is_flex_algo()`, which only accepts an explicit X-bit in the first SABM octet. A peer advertising Min/Max Link Delay in an ASLA with both SABM and UDABM empty is therefore ignored. `graph_v3_flex_algo` treats the link as having no delay and prunes it, potentially removing the only path from the Flex-Algo topology.

[RFC9492 section 5](https://www.rfc-editor.org/rfc/rfc9492.html#section-5) requires using zero-length-mask attributes when no matching non-zero-length application advertisement exists. When a matching application advertisement exists, the zero-mask advertisement must not be used. The reader needs this selection rule rather than an X-bit-only filter. The existing affinity reader has the same restriction, but this change newly applies it to delay and edge reachability.

Reproduction: supply an otherwise valid peer E-Router-LSA with a P2P Router-Link, empty application masks, and Min/Max Link Delay. The delay join table contains no entry for that interface despite the decoded metric. Add coverage for zero-mask-only input, explicit-X input, explicit-X precedence in both advertisement orders, and an unrelated application's mask.

### 3. P2 — Peer link-local renumbering leaves STAMP probing the old address

Location: [inst.rs](../../zebra-rs/src/ospf/inst.rs:10616), `Message::NbrSourceChanged`.

The receive path updates the neighbor's IPv6 source address and sends `NbrSourceChanged` without requiring the adjacency to leave Full. That handler reconciles BFD and End.X and schedules SPF, but does not call `stamp_reconcile_and_originate`. The newly enabled OSPFv3 STAMP subscription therefore retains its old remote endpoint. Subsequent Hellos in Full do not cause the state-transition reconciliation to run.

Reproduction: replace a Full neighbor's link-local address while preserving its Router-ID and Hello adjacency. OSPF follows the new source, but the tracked STAMP key still names the deleted address. Measurements stop or expire and delay advertisements become unavailable until another state transition or measurement configuration edit reconciles the subscription.

Reconcile STAMP in the source-change handler so the old subscription ends, its measured values are cleared, and a subscription for the new address is created. Verify this with a renumber while the adjacency remains Full.

## Implementation status

| Capability | Status |
|---|---|
| Static average delay, min/max delay, variation, loss | Configuration and ASLA rendering implemented |
| OSPFv3 performance attribute codec | Types 13–16 implemented; codec test checks code points and A-bit round trip |
| Per-value anomaly flags and static-over-measured merge | Shared with OSPFv2; OSPFv3 rendering implemented |
| IPv6 P2P STAMP measurement | Subscription, event-loop consumption, and E-Router-LSA refresh implemented; renumber gap above |
| Delay-based Flex-Algo SPF | Delay join and missing-delay pruning implemented; local recalculation and zero-mask selection gaps above |
| Advertisement without SR | Not supported: origination requires SR-MPLS or active SRv6; documented in YANG |
| Measured loss and bandwidth metrics | Not supplied by this change; loss is static-only and bandwidth variants are absent |
| Live route-selection validation | Not established by this review |

The OSPFv3 code points agree with [RFC9492 section 14.2](https://www.rfc-editor.org/rfc/rfc9492.html#section-14.2). The shared value encoding does not imply use of OSPFv2 TE Opaque LSA type numbers.

## Validation and coverage limits

- `cargo test -p zebra-rs --bin zebra-rs ospf:: -- --nocapture`: 108 passed.
- `cargo test -p ospf-packet ospfv3_asla`: 3 passed.
- BDD features/configuration were inspected, not executed during this review.

The IPv6 STAMP topology enables SR-MPLS and checks metric presence and shared subscribers. It does not exercise delay-based path selection, zero-mask interoperability, or endpoint renumbering. Its comment claiming OSPFv3 needs no segment routing contradicts the implementation and configuration. The static-metric feature's comment that the average is unpinned also contradicts its stated static average configuration. These comments should be corrected when extending the tests.

The uncommitted display change uses a colon for Min/Max Link Delay, while the IPv6 feature's negative assertion still searches for `Min/Max Unidirectional Link Delay = 0/0 usec`. That check will no longer detect zero bounds after the display change; update the assertion to match the rendered output.

Passing unit tests establish builder and codec behavior, not resolution of the three lifecycle/selection findings above or live controller delivery.
