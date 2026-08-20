# IS-IS TI-LFA Micro-loop Avoidance — Design

Status: IMPLEMENTED — native algorithm-0 slice (2026-08-20)

Implementation scope: the landed slice provides the per-level
candidate/hold controller, RIB activation acknowledgement, stale-SPF
revision gate, a per-level self router-LSP generation commit gate, native
IPv4/IPv6 route partitioning, fixed timer, configuration/show surfaces, and
BFD topology coverage. The generation gate preserves an affected protected
route even when a pre-commit SPF omits it entirely, while post-commit
withdrawals remain immediate. The graph-delta classifier, explicit
`Suppressed` phase, Flex-Algorithm/ILM delay, and the additional
physical-link/SRv6 BDD cases described below remain follow-up
hardening/coverage rather than claims about this initial slice.

This document designs the first zebra-rs micro-loop avoidance feature:
an IS-IS-local, TI-LFA-backed RIB update delay. OSPF is deliberately
out of scope for the first implementation, but the state machine and
publish boundary are shaped so OSPF can reuse them later.

The standards basis is [RFC 8333](https://www.rfc-editor.org/rfc/rfc8333.html)
(local convergence delay) together with
[RFC 9855](https://www.rfc-editor.org/rfc/rfc9855.html) (TI-LFA).
RFC 9855 is explicit that TI-LFA alone does not prevent distributed
convergence micro-loops: releasing a repair before downstream routers
have converged can create one, and local convergence delay is one way
to prevent that early release.

## 1. Decision

When this router detects a single local IS-IS adjacency/link loss:

1. Activate the already-installed TI-LFA repair immediately. The
   existing `Nexthop::Protect` fast path does this with an atomic
   nexthop-group replacement for BFD loss; this design generalizes the
   same operation to adjacency expiry. Kernel link-down performs the
   equivalent promotion autonomously.
2. Originate/flood the topology change and compute SPF/TI-LFA normally.
3. Publish unrelated, new, and withdrawn routes immediately.
4. For each changed route that was protected against the failed local
   resource, keep its old, active TI-LFA repair in the RIB/FIB for a
   configured delay.
5. At expiry, publish the latest post-convergence route and its newly
   computed repair for the next failure.

The timer delays **route publication**, not LSP flooding or SPF. That is
the important architectural boundary: other routers must learn the
failure promptly, and zebra-rs must still compute and retain the latest
desired state while forwarding remains on the old repair.

The initial mode is always **protected-prefix only**. An unprotected
old route is never retained after its primary fails. This is safer than
an instance-wide blind delay and directly matches the request to build
micro-loop avoidance on TI-LFA.

## 2. What this does and does not guarantee

### 2.1 Covered in the first implementation

- IS-IS Level 1 and Level 2, with independent per-level state.
- IPv4/SR-MPLS and IPv6/SRv6 `Nexthop::Protect` routes.
- The IPv6 MT-2 RIB, which already flows through `rib_v6`.
- Local physical-link down, BFD down while the link remains up, and
  IS-IS adjacency expiry, provided the repair was demonstrably
  activated.
- A single local failure epoch. A second or ambiguous topology event
  aborts the delay and converges normally.

This prevents loops involving the local point of repair (PLR), which is
the scope of RFC 8333. It is incrementally deployable and requires no
new IS-IS TLV or neighbor capability.

### 2.2 Explicit non-goals

- Remote micro-loops that do not involve this PLR.
- Link-up, metric-change, overload-bit, prefix-only, or other remote
  topology events.
- Ordered FIB (RFC 6976) and network-wide convergence ranks.
- Temporary post-convergence SR policies computed on every router.
  That is the broader “SR micro-loop avoidance” mechanism; it requires
  old/new topology path encoding and is not the same as retaining a
  precomputed TI-LFA repair.
- Multiple simultaneous failures or SRLG failure correlation.
- OSPFv2/OSPFv3 implementation in this series.
- Flex-Algorithm RIBs and MPLS ILM publication delay. They remain
  immediate in the first implementation and are the next dataplane
  extension after native algorithm-0 IPv4/IPv6.

Incoming SR-MPLS Prefix-SID traffic also needs the corresponding ILM to
carry `Nexthop::Protect` before it can claim the same protection. Today
`mpls_route()` retains backup information in `SpfIlm`, but
`make_ilm_entry()` renders only a `Uni`/`Multi` primary. Native IP and
recursively resolved traffic are covered first; protected ILMs are a
separate implementation slice (Slice E in Section 14).

## 3. Current behavior and the gap

The current pipeline is:

```text
local failure
  -> TI-LFA protection group switches to its repair
  -> self LSP is regenerated and flooded
  -> Message::SpfCalc(level)
  -> build_spf_input()
  -> spawn_blocking(compute_spf)          # SPF + new TI-LFA repairs
  -> Message::SpfDone(output)
  -> apply_spf_result()
  -> apply_routing_updates()
  -> diff_apply()                         # post-convergence RibAdd
```

`apply_spf_result()` currently replaces the old route within
milliseconds. Re-adding a protected route also causes
`resolve_nexthop_protect()` to return its protection group to
`ProtectActive::Primary`. The repair is therefore an intentionally
short bridge, as documented in
`docs/design/nexthop-protect-kernel-failover.md`.

That early release is the micro-loop window. The new first hop may
still forward according to the old topology and send the packet back
to this router. The desired sequence is instead:

```text
failure     SPF done             delay expires
   |           |                       |
   v           v                       v
primary -> old TI-LFA repair -----> new SPF primary
           (other routers converge)
```

The repair to retain is the one attached to the **old published
route**. A repair computed by the post-failure SPF protects against a
future failure in the new topology; it must not replace the repair for
the failure currently in progress.

## 4. Configuration

Add a presence container beside `ti-lfa` under the existing IS-IS
`fast-reroute` container:

```yang
container micro-loop-avoidance {
  presence "Enable TI-LFA-backed local micro-loop avoidance";
  leaf rib-update-delay {
    type uint32 { range "1..60000"; }
    units milliseconds;
    default "5000";
  }
}
```

Example configuration:

```text
router isis {
  segment-routing mpls;
  fast-reroute {
    ti-lfa;
    micro-loop-avoidance {
      rib-update-delay 5000;
    }
  }
}
```

Equivalent set syntax:

```text
set router isis fast-reroute ti-lfa
set router isis fast-reroute micro-loop-avoidance rib-update-delay 5000
```

Decisions:

- Disabled by default.
- A bare `micro-loop-avoidance` uses 5000 ms.
- The timer range is 1..60000 ms. Operators should set it above the
  measured worst-case network convergence time.
- Do not add a YANG `must` tying the container to `ti-lfa`. Config
  transaction ordering and temporarily staged configuration should
  remain flexible. Runtime state reports `inactive: ti-lfa disabled`
  until both are enabled and an SR dataplane can build repairs.
- Changing or deleting this configuration during an active hold is a
  fail-open operation: cancel the timer and publish the latest pending
  snapshot immediately. A future event uses the new value.
- `fast-reroute backup-as-primary` is a repair-test knob and is not
  combined with micro-loop avoidance. When it is set, MLA reports
  inactive rather than trying to reinterpret the inverted roles.

Add these fields to `isis::config::IsisConfig`:

```rust
pub micro_loop_avoidance: bool,
pub micro_loop_rib_update_delay_ms: u32, // default 5000
```

Configuration callbacks live in `isis/config.rs`. Enabling the knob
does not originate an LSP and does not need an SPF: it changes only the
next eligible convergence event. Disable/config-change must send a
controller flush message if a hold is active.

## 5. Failure identity and eligibility

Blindly delaying every `SpfDone` is unsafe. The controller first needs
proof of a local failure and then decides per route whether the old
repair covers it.

### 5.1 Local failure hint

Before tearing down an adjacency, capture:

```rust
struct LocalFailure {
    id: u64,
    level: Level,
    cause: FailureCause,       // LinkDown | BfdDown | AdjacencyExpired
    ifindex: u32,
    peer: IsisSysId,
    peer_vertex: Option<usize>,
    pseudonode: Option<IsisNeighborId>,
    nexthops: BTreeSet<IpAddr>,
    detected_at: Instant,
}
```

The capture must happen while the neighbor entry still holds its IPv4
and IPv6 link-local addresses. Refactor the duplicate address capture
in `process_bfd_down()` into the common adjacency-teardown path so BFD
and hold-timer expiry have identical protection behavior.

`link_state_down()` creates one hint per affected level before it drops
the neighbor maps. A physical link-down needs no `ProtectSwitch`: the
RIB/kernel link-down path already invalidates the primary and promotes
the installed shadow repair.

For BFD and adjacency expiry with an operational link, call
`RibClient::protect_switch()` before SPF. Extend the request with a
failure cookie and return a targeted result to IS-IS:

```rust
Message::ProtectSwitch { addr, cookie }
RibRx::ProtectSwitchResult {
    cookie,
    addr,
    rewired_protect_groups,
    evicted_ecmp_groups,
}
```

The existing RIB function already returns `(switched, evicted)`, so
this is an API plumbing change, not a new dataplane operation. A
link-up failure is eligible only after at least one protection group
was rewired. If the result has `rewired_protect_groups == 0` (including
`--no-nhid`), converge immediately; holding a dead primary without
proof of repair would turn protection into a black hole. ECMP eviction
alone does not qualify a route for the delay.

### 5.2 Topology validation

The implemented native slice first uses an explicit local commit gate. Each
complete self router-LSP set increments a per-level generation exactly once,
after every fragment and trailing-fragment purge is in the LSDB. A failure
candidate records the next required generation, and `SpfInput` stamps the
generation of the graph it actually built. Therefore an SPF started against
the pre-failure self LSP remains ineligible even if it completes after the
new LSP is installed. While waiting, only old protected routes matching the
failed resource are restored into the published snapshot, including a route
omitted from desired RIB; unrelated changes continue immediately. A bounded
internal watchdog derived from the existing LSP-generation and SPF maximum
waits fails open if the commit or activation never completes. No new operator
timer is required.

The graph-delta classifier below remains the stricter follow-up design:

A local event hint is necessary but not sufficient. Add a monotonically
increasing per-level `topology_revision`, stamp it into `SpfInput` and
`SpfOutput`, and compute the graph delta before `build_spf_input()`
replaces `top.graph[level]`.

A candidate remains eligible only when the topology delta describes
the hinted resource:

- one local outgoing adjacency on the captured ifindex disappeared;
- the matching reverse edge may disappear in the same or a later SPF;
- for a broadcast circuit, the equivalent local-router/pseudonode
  edges are accepted;
- no edge was added, no other edge disappeared, and no unrelated
  metric changed.

An LSP refresh with identical topology is ignored. Any delta the
classifier cannot prove belongs to the same failure is “foreign” and
aborts the candidate/hold. This intentionally prefers ordinary
convergence over a questionable delay.

If an SPF was snapshotted before the failure but finishes afterwards,
its revision is stale. Do not publish that output. The existing
`spf_pending` latch must drive the already-scheduled fresh run. This
also removes a pre-existing, short stale-SPF publication window.

### 5.3 Per-route eligibility

Only a `different` old/new prefix is deferred, and only when all of
the following hold:

1. The old published route has exactly one primary nexthop.
2. That nexthop matches the failure's ifindex, peer system ID, or
   captured gateway address.
3. The old nexthop has a non-empty TI-LFA backup.
4. The RIB confirmed activation for a link-up failure, or the failure
   is a physical link-down with autonomous kernel promotion.
5. A usable new route exists and no longer uses the failed resource.
6. `backup-as-primary` is off.

Use a primary-only comparison helper: a change only to the repair for
the *next* failure must not be mistaken for a primary transition.

The other table-diff classes are deliberately immediate:

| Diff class | Action | Reason |
|---|---|---|
| `only_curr` (withdrawal) | immediate delete | never retain a possibly dead destination |
| `only_next` (new prefix) | immediate add | there is no old forwarding state to loop through |
| `different`, unprotected | immediate add/delete | no safe repair exists to retain |
| `different`, unrelated primary | immediate add | not traffic using the failed local resource |
| `different`, eligible protected primary | defer | old repair is active and loop-free |
| `identical` | no-op | preserve current state |

## 6. State machine

Maintain one controller per IS-IS level:

```rust
enum MlaPhase {
    Idle,
    Candidate(Candidate),
    Holding(Hold),
    Suppressed { until_revision: u64 },
}

struct Hold {
    token: u64,
    failure: LocalFailure,
    started_at: Instant,
    deadline: Instant,
    timer: Timer,
    latest: IsisRouteSnapshot,
    deferred: DeferredCounts,
}
```

`Suppressed` means a second/ambiguous event occurred. It prevents a
multi-failure burst from being misclassified as a new single failure;
one current-revision SPF is published normally before the controller
returns to `Idle`.

```text
Idle
  | proven local failure
  v
Candidate
  | current SPF + matching delta + active repair + eligible route(s)
  v
Holding ---------------- timer expiry ----------------> Idle
  |                          publish latest
  |
  +-- same failure update --> replace latest, keep original deadline
  |
  +-- foreign/second event --> publish latest --> Suppressed
  |
  +-- disable/config change -> publish latest ----------> Idle

Candidate -- no repair / no eligible route / bad delta --> normal publish --> Idle
Candidate -- foreign/second event ----------------------> Suppressed
```

Timer messages carry their token:

```rust
Message::MicroloopExpire { level, token }
Message::MicroloopAbort { level, token, reason }
```

Dropping `Timer` cancels its task; checking the token makes an already
queued stale expiry harmless.

The deadline starts when the first qualifying post-failure SPF reaches
the publish boundary, not when BFD detects the failure. This gives
remote routers the full configured convergence interval after the
topology has been flooded/computed. A matching follow-up SPF replaces
`latest` but never extends the deadline, so LSP churn cannot retain the
repair indefinitely.

## 7. Separate desired state from published state

The current `top.rib`, `top.rib_v6`, `top.rib_flex_algo`,
`top.rib6_flex_algo`, and `top.ilm` maps serve both as show state and as
the next `table_diff()` baseline. During a hold, “latest SPF result” and
“published forwarding state” are different, so that implicit coupling
must become explicit.

Introduce a materialized snapshot:

```rust
struct IsisRouteSnapshot {
    v4: PrefixMap<Ipv4Net, SpfRoute<V4>>,
    v6: PrefixMap<Ipv6Net, SpfRoute<V6>>,
    flex_v4: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute<V4>>>,
    flex_v6: BTreeMap<u8, PrefixMap<Ipv6Net, SpfRoute<V6>>>,
    flex_srv6_export: BTreeMap<u8, BTreeMap<IpNet, Ipv6Addr>>,
    ilm: BTreeMap<u32, SpfIlm>,
}
```

Refactor `apply_spf_result()` into three conceptual stages:

```text
1. accept_spf_result
   update graph/SPF/TI-LFA caches and telemetry

2. materialize_route_snapshot
   build v4/v6/flex/ILM desired tables without publishing them

3. publish_route_snapshot
   table_diff against the published snapshot and send RIB messages
```

The controller sits between stages 2 and 3. Its partition operation
constructs a partially published snapshot:

- eligible prefixes retain their old published value;
- every immediate class takes its new desired value;
- `Hold.latest` owns the full latest desired snapshot.

At expiry, diff the partially published snapshot against
`Hold.latest`. Updates already sent immediately compare identical; only
the held transitions remain.

The existing `top.rib*` maps should continue to mean **published**
state so existing show output and diff logic remain truthful. The
latest SPF and TI-LFA graph caches continue to update immediately.
`show isis micro-loop-avoidance` explains the intentional difference.

Do not sleep in `SpfDone`, block the IS-IS actor, or defer the whole
`SpfOutput`: LSDB processing, subsequent SPF coalescing, BFD recovery,
show commands, and abort events must remain live throughout the delay.

## 8. Side effects around route publication

`apply_spf_result()` currently mixes route publication with other
side effects. Split them by semantics:

- Update graph, SPF result, TI-LFA result, and compute telemetry
  immediately.
- Recompute and register Mirror-SID egress protections immediately;
  those registrations reflect LSDB state, not this route hold.
- Reconcile the local self Prefix-SID ILM immediately; it is derived
  from local configuration, not the remote SPF.
- Publish/defer algorithm-0, MT-2, and Flex-Algorithm route snapshots
  through the MLA controller.
- In the first slice, publish transit ILM changes immediately and count
  them as `unsupported_ilm`; Slice E in Section 14 closes that coverage
  gap.
- Run BGP-LS production from accepted LSDB/SPF state immediately. MLA
  is a local forwarding decision and must not delay topology export.

When BFD recovers during a hold, publish the pending post-failure routes
**before** sending `ProtectRestore`. Otherwise the restore can briefly
reactivate the old failed primary. Both operations use the same RIB
client channel, so this ordering is enforceable.

## 9. Handling another event during the delay

RFC 8333 requires the delay to stop when a new convergence occurs. In
this design:

1. A topology-change hook classifies the change against the current
   failure signature.
2. A matching peer-side removal for the same failed adjacency may
   update `Hold.latest`; the deadline is unchanged.
3. Any other local failure, link recovery, edge/metric change, manual
   SPF with changed topology, SR dataplane removal, or ambiguous delta
   queues `MicroloopAbort`.
4. Abort publishes the latest complete pending snapshot, cancels the
   timer, and enters `Suppressed` until the next current SPF has been
   published normally.

If the foreign event arrives while still `Candidate`, there may be no
pending snapshot to flush. Clear the candidate, mark the current
revision suppressed, and allow its fresh SPF to publish normally.

Prefix-only additions and withdrawals do not invalidate the failure
epoch because they are never delayed. They publish immediately and are
also folded into `Hold.latest`, preventing timer expiry from undoing
them.

## 10. Observability

Add:

```text
show isis micro-loop-avoidance
```

Example:

```text
Micro-loop avoidance: enabled
  Mode: TI-LFA protected-prefix local delay
  RIB update delay: 5000 ms
  L1: idle
  L2: holding, 3178 ms remaining
      cause: bfd-down, peer 0000.0000.0002, ifindex 8
      failure-id: 42, topology-revision: 177
      deferred: ipv4=814 ipv6=802
      immediate: add=2 delete=1 change=4
      repair activation: groups=9
```

When configured but unusable:

```text
Micro-loop avoidance: inactive (TI-LFA disabled)
```

Support JSON with stable fields for enabled/effective state, delay,
phase, cause, peer, ifindex, remaining milliseconds, revision, counts,
last completion reason, and cumulative counters.

Cumulative per-level counters:

- eligible local failures;
- candidates rejected by reason (`no-repair`, `no-fast-activation`,
  `ambiguous-delta`, `backup-as-primary`, `stale-spf`);
- holds started and expired;
- holds aborted by reason;
- prefixes deferred by AFI/topology;
- maximum and last actual hold duration;
- unsupported protected ILMs observed.

Log only state transitions at info level (`armed`, `expired`,
`aborted`), with one summary line rather than one line per prefix.
Per-prefix decisions belong behind IS-IS tracing.

The dedicated command owns convergence-state counters; the existing
`show isis fast-reroute summary` remains a TI-LFA protection inventory.

## 11. Safety rules

These invariants are load-bearing:

1. **Never delay without an old repair.** New-SPF TI-LFA state is not
   proof that the old route survived the current failure.
2. **Never delay an authoritative withdrawal.** A withdrawal from an SPF
   stamped with the required post-failure self-LSP generation is immediate.
   A matching protected route omitted by an earlier generation is a
   transitional snapshot and is retained until the commit gate resolves.
3. **Never delay without repair activation evidence** when the link is
   still operational.
4. **Never re-add a held protected prefix before expiry.** RIB route
   resolution would reset `ProtectActive::Switched` to `Primary`.
5. **Never extend the original deadline** for matching follow-up SPFs.
6. **Abort on uncertainty or a second event.** TI-LFA only promises
   the modeled single failure.
7. **A stale SPF cannot publish.** Its topology revision predates the
   event it would overwrite, or its self-LSP generation predates the
   candidate's required local-topology commit.
8. **Timer cancellation is generation-safe.** A queued old expiry is a
   no-op.
9. **Configuration removal flushes, not drops, pending state.**
10. **Protocol shutdown bypasses MLA.** Cleanup/withdrawal must never
    wait for the update-delay timer.

Additional guards:

- Do not arm when `distribute.rib` is disabled.
- Graceful-restart hold-back takes precedence; MLA is idle while the
  restarter is holding the FIB.
- A route whose new primary still references the failed interface is
  ineligible and publishes normally (usually as a delete after empty
  nexthop collapse).
- L1 and L2 timers are independent, but a physical interface event may
  create candidates for both levels with the same failure ID.
- Per-VRF IS-IS instances own independent controllers and timers.

## 12. Unit tests

Put the pure partition and state-machine tests in
`isis/microloop.rs`.

Partition matrix:

- changed single-primary route, matching failed nexthop, backup present
  -> deferred;
- matching route without backup -> immediate;
- unrelated protected route -> immediate;
- new route -> immediate;
- withdrawal -> immediate;
- ECMP route -> immediate;
- new route still using failed resource -> immediate/fail open;
- only the future backup changed -> immediate;
- `backup-as-primary` -> immediate/inactive;
- IPv4, IPv6, MT-2, and per-algorithm keys stay isolated.

State-machine matrix (with a fake clock):

- `Idle -> Candidate -> Holding -> Idle` on expiry;
- no eligible prefixes returns directly to `Idle`;
- zero rewired groups rejects a BFD/hold-timeout candidate;
- matching reverse-edge update replaces `latest` without extending the
  deadline;
- second failure/foreign delta aborts and enters `Suppressed`;
- config disable flushes;
- BFD recovery flushes before restore;
- stale SPF output is ignored;
- stale timer token is ignored;
- L1 and L2 holds do not overwrite one another;
- a prefix added/withdrawn during a hold is not resurrected at expiry.

RIB API tests:

- `ProtectSwitchResult` is returned only to the requesting protocol;
- cookie and table/VRF scope survive the round trip;
- `rewired=0` on `--no-nhid`/no candidate;
- ECMP eviction is reported separately and does not count as a TI-LFA
  repair activation.

## 13. BDD coverage

Extend the existing `@tilfa_bfd` topology rather than creating another
eight-node lab for the base case.

1. Configure a visibly long delay (for example 4000 ms).
2. Set the source SPF throttle to 1 ms and its self-LSP-generation throttle
   to 1000 ms, forcing the pre-commit SPF ordering window.
3. Drop BFD control packets while the data link and IS-IS IIHs remain
   up.
4. Assert the log reports `awaiting self-LSP generation` and the RIB reports
   protection-group rewiring.
5. Assert the post-commit SPF completes while
   `show isis micro-loop-avoidance` remains
   `holding`.
6. During the hold, assert the active nexthop is the repair and still
   carries its MPLS label stack (or SRv6 segment list), rather than the
   plain post-convergence route.
7. Run continuous traffic across the SPF-complete boundary and assert
   no loss attributable to early repair release.
8. After expiry, assert the plain post-convergence route is primary and
   the controller is idle.
9. Delete the temporary SPF/LSP timer leaves so their built-in defaults are
   restored.

Add focused scenarios for:

- physical link-down autonomous promotion;
- non-BFD adjacency expiry using `ProtectSwitch` before teardown;
- SRv6 parity;
- an unprotected prefix changing immediately during another prefix's
  hold;
- second link failure aborting the hold;
- link recovery aborting the hold;
- disabling MLA or TI-LFA during a hold;
- remote-only link failure and link-up not arming local-delay MLA;
- `--no-nhid` BFD failure rejecting the delay;
- timer expiry after a matching follow-up SPF uses the newest desired
  snapshot.

The existing BDD comment saying the switched state is “superseded
within milliseconds” must be updated: with MLA enabled, persistence
through the configured RIB-update delay is now the behavior under test.

## 14. Implementation slices

### Slice A — publish-boundary refactor (behavior-neutral)

- Add `IsisRouteSnapshot`.
- Split materialization from publication in `isis/rib.rs`.
- Keep existing maps as the published-state diff baseline.
- Add equivalence tests proving every current diff emits the same RIB
  messages with MLA disabled.

### Slice B — failure identity and RIB acknowledgement

- Add per-level topology revisions and stamp SPF input/output.
- Capture `LocalFailure` before adjacency/link teardown.
- Generalize fast repair activation to IS-IS adjacency expiry.
- Add the cookie-bearing `ProtectSwitchResult` RIB API.
- Reject stale SPF publication.

### Slice C — controller, config, and show

- Add `isis/microloop.rs` with the state machine and pure partitioner.
- Add YANG/config callbacks and `Message::MicroloopExpire/Abort`.
- Add text/JSON show output and transition counters.
- Implement config-disable, recovery, shutdown, and foreign-event
  abort ordering.

### Slice D — native IPv4/IPv6 dataplane BDD

- Extend SR-MPLS BFD coverage.
- Add physical-link and abort tests.
- Add SRv6 parity.
- Document operator behavior in the book and TI-LFA playsets.

### Slice E — SR-MPLS ILM protection

- Render a Prefix-SID `SpfIlm` with an old TI-LFA backup as
  `Nexthop::Protect`, using the repair stack as the MPLS new-destination
  operation.
- Verify `ProtectSwitch` rewires both IP routes and incoming-label ILMs.
- Include protected ILM transitions in the delayed snapshot and remove
  the `unsupported_ilm` qualification/counter.
- Add transit-label packet captures, not only locally originated ping.

Each slice should be independently reviewable; Slice A must land
without changing forwarding behavior.

## 15. Why not the alternatives

### Delay SPF or the IS-IS actor

Rejected. Flooding and SPF must continue promptly, and the actor must
remain responsive to a second failure, recovery, show requests, and
timer cancellation. RFC 8333 delays RIB/FIB update, not topology
distribution.

### Delay every route in the level

Rejected for the TI-LFA-backed first implementation. It would retain
unprotected routes and withdrawals, exactly where no safe forwarding
state exists. A later explicit “all prefixes” mode would need a safe
temporary SR path, not just a timer.

### Install the new SPF route and keep its new TI-LFA backup active

Rejected. That backup protects a possible next failure in the new
topology; it is not necessarily a repair for the failure in progress.
The safe state is the old route's already-activated repair.

### Implement ordered FIB first

Rejected for this series. Ordered FIB offers broader guarantees but
requires old/new SPT ranking and coordinated network timing. Local
delay reuses the protection and event machinery already present and
requires no interoperability protocol.

### Build temporary post-convergence SR policies now

Deferred. This is the right future mechanism for remote events,
link-up, metric changes, and all-prefix coverage. It needs a separate
old/new topology path encoder, SID-depth handling, fallback behavior,
and temporary policy lifecycle. Reusing the name “TI-LFA” for that
work would obscure that it is computed after the event rather than
pre-installed for local repair.

## 16. OSPF later

Do not add OSPF config or event hooks in this series. Keep the reusable
seams narrow:

- a protocol-neutral timer/token shell;
- a generic table-diff partition helper parameterized by an eligibility
  predicate;
- the cookie-bearing RIB repair-activation result;
- a snapshot publish contract: latest desired state versus currently
  published state.

IS-IS retains ownership of adjacency/pseudonode failure classification
and route matching. A future OSPF port supplies area/interface/neighbor
identity and LSA topology-delta validation without forcing IS-IS data
types into shared code.

## 17. Acceptance criteria

The feature is complete when all of the following are true:

- A BFD- or link-down-triggered, TI-LFA-protected IS-IS route remains
  on its pre-failure repair after SPF completes and for the configured
  delay.
- The latest post-convergence route replaces it at expiry.
- Withdrawals and unprotected changes are never delayed.
- A second/ambiguous event or recovery cancels the hold and converges
  normally.
- No old timer or stale SPF can overwrite newer state.
- SR-MPLS and SRv6 native routes behave identically.
- Text and JSON show output explain whether the feature is inactive,
  candidate, holding, expired, or aborted and why.
- MLA-disabled behavior is message-for-message equivalent to the
  current pipeline.
- The documentation states the local-loop guarantee and does not claim
  remote/link-up micro-loop prevention.
