BGP path selection and UPDATE adversarial review
===============================================

Reviewed commit: `2f1e9a09` (2026-09-07). Review of the current implementation, not a proposed diff. No production fixes applied. Some issues were already noted in `docs/design/bgp-code-review-findings.md`; findings below were checked against the current code rather than treating that older document as authoritative.

Nine actionable findings follow. P1 means high-impact correctness failure in the stated configuration; P2 means a best-path consistency defect. Seven added probes expose six findings; the other three findings are established by control-flow inspection, not live-router reproduction.

Validation
----------

- Existing BGP-filtered tests: **907 passed, 0 failed**, using `RUST_BACKTRACE=0 target/debug/deps/zebra_rs-514a95517e47badd bgp:: --skip adversarial_review` (the no-default-features test binary).
- Added adversarial probes: **7 failed at the expected assertions**, not at setup or compilation. See [captured output](targeted-test-output.txt).
- [Reproducer patch](regression-tests.patch) contains tests only; it is saved unapplied so the source tree retains its original behavior. The patch intentionally introduces failing tests.
- To reproduce from the reviewed commit: `git apply docs/reviews/bgp-path-update-2026-09-07/regression-tests.patch`, then `RUST_BACKTRACE=0 cargo test -p zebra-rs --bin zebra-rs adversarial_review --no-default-features`.
- The ECMP probe checks the selection-vector contract used by egress; it does not run a complete session. The policy probe exercises IPv6 fan-out and verifies the denied route enters Adj-RIB-Out. The group-task probe captures its outbound packet channel.
- No network topology, external peer interoperability, default-feature/Lua test suite, or full sharded deployment was executed. Passing existing unit tests is not evidence of correctness for untested combinations.

1. [P1] IPv6 unicast AddPath bypasses outbound policy
--------------------------------------------------

Location: `zebra-rs/src/bgp/route.rs:13270–13279`, in `route_advertise_to_peers_v6`.

Configure an IPv6-unicast AddPath-Send peer with a DENY-ALL outbound route-map, then receive a new IPv6 route. The candidate loop calls `route_update_ipv6`, interns its output immediately, and queues `send_ipv6`. It never calls `route_apply_policy_out_v6`, so native outbound route-map/prefix-list denial and attribute rewrites are bypassed. The ordinary non-AddPath path and the session-up IPv6 dump do apply that policy, making behavior dependent on AddPath and whether the route arrived before or after session establishment.

Evidence: `adversarial_review_v6_addpath_honors_deny_policy` fails because the denied prefix appears in the peer's Adj-RIB-Out after the real fan-out call.

Fix direction: evaluate outbound policy for every candidate before recording/queuing it, and use the existing old/new path-ID diff to withdraw newly denied candidates.

2. [P1] Attribute replacement leaves stale entries in update-group caches
----------------------------------------------------------------------

Locations: `zebra-rs/src/bgp/update_group.rs:704–710` and `1237–1243`; removal at `723–730` and `1251–1259`.

During one advertisement interval, queue prefix P with attributes A, update P to attributes B, then withdraw P. Each enqueue inserts into a new attribute bucket and overwrites the reverse map, without removing the prior bucket entry. Withdrawal follows the reverse map to B and removes only B; A remains queued and the subsequent flush re-advertises the withdrawn prefix. Without the withdrawal, the same NLRI can be emitted with both old and new attributes in hash-map-dependent order.

This affects default IPv4/IPv6 unicast update groups with AddPath off and on. The two probes exercise both wire IDs 0 and 7 and fail with stale entries for both IDs.

Fix direction: atomically evict a previous NLRI-to-attribute association before inserting the replacement, preserving the forward/reverse invariant.

3. [P1] Rejected AddPath replacements leave the previous advertisement installed
------------------------------------------------------------------------------

Locations: `zebra-rs/src/bgp/route.rs:5614–5632`, `5811–5831`; caller at `4717–4725`.

Advertise a path to an AddPath peer, then reannounce the same source prefix/path-ID with changed attributes that cause an outbound denial, NO_ADVERTISE/NO_EXPORT suppression, or a VPN RTC mismatch. The advertise helpers return without removing pending cache entries, deleting Adj-RIB-Out, or sending an MP_UNREACH. In `apply_ipv4_advertise_job`, an accepted inbound replacement produces `added = Some(...)`, so the replaced-path withdrawal branch is not run either. The receiver retains the old allowed version indefinitely absent a later corrective event.

Affected paths: default IPv4 unicast AddPath, VPNv4 AddPath, and VPNv6 AddPath. The dedicated IPv6 unicast diff loop and labeled-unicast diff loop have different control flow and should not be conflated with these helpers.

Evidence: the VPNv4 helper probe seeds a previously advertised path and applies an outbound-denied replacement; the old Adj-RIB-Out entry survives. The probe is named `adversarial_review_v4_addpath_denied_replacement_withdraws`.

Related inspected gaps: EVPN `evpn_advertise_one` (`6682–6687`) and MUP `mup_advertise_one` (`10043–10050`) also return on export suppression without withdrawing a previous advertisement, including with AddPath off. FlowSpec fan-out (`11182–11184`) similarly skips a newly split-horizon-blocked peer instead of withdrawing its former route. These extensions were inspected, not exercised by the probe.

Fix direction: make export rejection an explicit withdrawal of the previously advertised wire key, including cache cleanup; do not equate rejection with “no change.”

4. [P1] EVPN AddPath does not withdraw a departed path when another candidate survives
-----------------------------------------------------------------------------------

Locations: `zebra-rs/src/bgp/route.rs:9579–9587` and `6711–6726`.

Let A be the EVPN winner advertised to an AddPath peer as ID a, with B retained as an alternate. Withdraw A. `route_evpn_withdraw` removes A locally but, because B survives, calls only `route_advertise_evpn_to_peers`. That emits B under a different local path-ID b and never sends the withdrawal for a. The receiver can retain the departed VTEP path and prefer it over B. A winner change without withdrawal similarly accumulates advertisements.

Both receive-time fan-out and the session-up dump (`15429–15433`) iterate selected winners, while EVPN soft-out walks all candidates for AddPath. Thus the candidate set sent also depends on which replay path is used.

Evidence: control-flow inspection. Under [RFC 7911 section 5](https://www.rfc-editor.org/rfc/rfc7911.html#section-5), a different path-ID does not implicitly replace the old path. Sending every candidate is an implementation policy choice; failing to remove a departed advertised ID is the correctness failure.

Fix direction: carry per-candidate deltas or diff advertised IDs against the eligible candidate set on every update/withdraw, regardless of whether a best path survives.

5. [P2] ECMP egress advertises the last alternate instead of the selected best path
-------------------------------------------------------------------------------

Locations: `zebra-rs/src/bgp/route.rs:5870`, `5214`, `5247`, `4434`, and `13794`.

`LocalRibTable::select_best_path` places the winner first (`2210–2211`) and appends ECMP alternates (`2263`). The ordinary unicast/VPN advertisement loop, IPv4 batch precompute, both optional IPv4 task fans, and labeled-unicast fan instead use `selected.last()`.

With maximum-paths greater than one and two eligible next-hops, a plain peer receives the alternate's attributes/next-hop rather than the Loc-RIB winner. Split horizon is evaluated against the alternate's source as well, so the wrong source peer is suppressed. Session-up dumps use the selected table, creating a before/after-sync inconsistency. A change in the ECMP set can change advertisements even while the actual winner stays fixed.

Affected plain-peer paths: IPv4/IPv6 unicast, VPNv4/VPNv6, and labeled IPv4/IPv6 wherever multipath is active. AddPath's independent candidate fan-out has a different contract.

Evidence: `adversarial_review_ecmp_egress_uses_actual_best` produces two ECMP rows and fails because the row selected by the egress expression has `best_path == false`.

Fix direction: use the first/winner row consistently; make the best-path and forwarding-set interfaces explicit.

6. [P1] Unicast next-hop knobs are absent from update-group signatures
-------------------------------------------------------------------

Location: `zebra-rs/src/bgp/update_group.rs:480–485`, plus `UpdateGroupSig`.

Two peers with the same effective policy, local session address, capabilities, and peer type can share a group even if only one enables unicast next-hop-self or next-hop-unchanged. The signature contains the VPNv4 versions but omits the IPv4/IPv6 unicast versions. The egress builders do read the unicast knobs (`peer.rs:1752–1757`, `route.rs:13025–13032`). The memoized first member's transform is consequently reused for members requiring a different NEXT_HOP; an unreachable preserved upstream next-hop can be sent where next-hop-self was required.

This affects ordinary IPv4/IPv6 unicast grouping. Differences applied before establishment are enough; this is separate from runtime regrouping bugs.

Evidence: `adversarial_review_unicast_nexthop_knob_splits_groups` changes IPv6 next-hop-self on one peer and fails because both signatures remain identical.

Fix direction: include both unicast next-hop knobs in the appropriate AFI/SAFI signature and regroup/replay when they change.

7. [P1] Group-task split horizon does not retract the previous route from a new source member
-----------------------------------------------------------------------------------------

Location: `zebra-rs/src/bgp/group_egress.rs:275–320`.

Requires `ZEBRA_BGP_EGRESS_GROUP_TASK=1`, IPv4 unicast, AddPath off. Start with P learned from external peer X and advertised to group members A and B. A then becomes the best path's source. The engine only fans the new advertisement to non-source members and never withdraws the X advertisement previously sent to A. Its attribute-pointer dedup can also suppress the fan altogether when the two transformed attributes match. A singleton group whose only member becomes the source takes the early return and has the same stale-route problem.

Evidence: `adversarial_review_best_becomes_member_requires_withdraw` captures the initial UPDATE delivered to A, changes the source to A, and fails because A receives no withdrawal.

Fix direction: account for old versus new per-member eligibility before deduplication; shared attributes do not imply identical recipient sets.

8. [P1] Per-peer egress mode drops incremental IPv4 AddPath advertisements
----------------------------------------------------------------------

Locations: `zebra-rs/src/bgp/route.rs:4712–4715` and `5214–5215`.

Enable per-peer egress tasks with group-task mode off and establish an IPv4 AddPath-Send peer. The update reducer unconditionally takes the PET branch for IPv4 unicast and returns before the AddPath `added/replaced` fan-out. `fan_advertise_to_pets` enumerates only `established_plain_idents`, which excludes AddPath-Send peers. Initial sync can send routes, but newly learned routes and attribute replacements no longer reach the AddPath peer through the ordinary update path.

Evidence: control-flow inspection, including the disjoint peer membership partitions and PET creation for AddPath peers in `peer.rs:2193–2196`. No task-mode integration reproduction was run.

Fix direction: implement candidate advertise/withdraw delivery to AddPath PETs, or keep those peers on the established AddPath update-group path until that support exists.

9. [P1] A pure SR Policy reflector forwards announcements but suppresses withdrawals
---------------------------------------------------------------------------------

Locations: `zebra-rs/src/bgp/route.rs:10452–10458` and `10501–10507`.

A valid SR Policy is targeted at a downstream headend rather than the reflector. `route_srpolicy_update` reflects it, then returns because it is not locally usable; no candidate is stored in the headend DB. On withdrawal, reflection is conditional on the headend DB removing a candidate. Nothing was stored, so the downstream withdrawal is suppressed and the receiver retains stale policy state.

This applies to both endpoint address families using the shared SAFI-73 path; AddPath Send is not implemented for this family. Evidence is current control-flow inspection, also consistent with the earlier design review note.

Fix direction: track transit SR Policy state independently of local headend usability, and use that state for withdrawal and peer-down cleanup while preserving no-op withdrawal suppression.

Coverage notes
--------------

| Area | Inspected behavior / findings |
|---|---|
| IPv4 unicast | Selection/ECMP, group memo/cache/flush, AddPath replacement, PET/group-task dispatch |
| IPv6 unicast | Selection/ECMP, group cache, candidate diff, outbound policy, session-up replay |
| VPNv4/VPNv6 | Shared best-path fan, candidate replacement, per-peer send/withdraw, RTC gates |
| Labeled IPv4/IPv6 | ECMP best selection; full candidate-ID diff and outbound policy inspected |
| EVPN | Winner/candidate tables, receive/withdraw, AddPath IDs, sync versus soft-out |
| MUP | Shared best-path comparator and export-suppression transition inspected |
| FlowSpec | Selection/validation/fan-out and split-horizon transition inspected |
| BGP-LS | Candidate selection table and AddPath transmit support boundary inspected; no dedicated finding asserted |
| SR Policy | Transit reflection versus headend storage and withdrawal |

The highest-value follow-up matrix is receive → replace attributes → deny export → withdraw best with a survivor → last-path withdrawal → peer-down → route refresh, crossed with AddPath Send on/off and all supported egress modes. Group tests should include members with different next-hop knobs, source membership, and negotiated capabilities. Each check should compare Loc-RIB, Adj-RIB-Out, pending caches, and the receiver's actual path-ID set.
