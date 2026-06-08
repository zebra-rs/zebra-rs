# BGP Update-Groups (IOS-XR style)

Status: **In progress** — Phases 1, 2, 3a-3d, 6a-1 landed for IPv4
unicast. Next up: more 6a sub-PRs (advertise + counter ratio,
split-horizon, withdraw, AddPath, soft-out direct, session join/leave),
then Phase 4, Phase 5, Phase 6b (VPNv4/EVPN BDD + polish). VPNv4 /
EVPN cache migration is a separate track also pending.
Owner: Kunihiro Ishiguro
Last updated: 2026-05-07

| PR  | Phase | Title                                                                  |
|-----|-------|------------------------------------------------------------------------|
| 441 | 1     | bgp: add update-group skeleton (signature + grouping + show)           |
| 442 | 2     | bgp: share outbound policy + transform per update-group                |
| 443 | 3a    | bgp: add update-group cache + flush scaffolding                        |
| 444 | 3b    | bgp: route IPv4 advertise through update-group cache                   |
| 445 | 3c    | bgp: route IPv4 addpath through update-group cache                     |
| 446 | 3d    | bgp: complete IPv4 update-group migration; drop per-peer cache         |
| 447 | 6a-1  | bgp: BDD coverage for IPv4 unicast update-group formation              |

## 1. Goal

Implement Cisco IOS-XR-style **update-groups** in zebra-rs: peers whose
outbound advertisement state is identical share the expensive part of
the advertise pipeline (attribute transform → outbound policy → encoded
UPDATE), so policy is run *once per group* instead of *once per peer*.

The optimization is **runtime only**: no YANG schema change, no new
configuration knobs, transparent to operators except for the new
observability commands.

## 2. Background — current state

### 2.1 Outbound pipeline

`route_advertise_to_peers` in `zebra-rs/src/bgp/route.rs:801` is the
canonical fan-out point. For each best-path change it iterates every
established peer and, per peer:

1. `route_update_ipv4(peer, prefix, rib, ...)` (route.rs:2157) —
   transforms attributes:
   - AS_PATH prepend (eBGP only).
   - NEXT_HOP rewrite (eBGP or originated, taken from
     `peer.param.local_addr` or `bgp.router_id`).
   - LOCAL_PREF defaulting (iBGP only).
   - ORIGINATOR_ID + CLUSTER_LIST manipulation (RR cases).
   - Split-horizon drop when `rib.ident == peer.ident`.
2. `route_apply_policy_out(peer, &nlri, attr)` (route.rs:561) — runs
   the per-peer outbound `prefix-set` then `policy-list`.
3. `bgp.attr_store.intern(attr)` — global interner for `Arc<BgpAttr>`,
   already shared across all peers.
4. `peer.adj_out.add(...)` + `peer.cache_ipv4.entry(attr).or_default()
   .insert(nlri)` — per-peer Adj-RIB-Out and per-peer pending-advert
   cache.
5. Adv timer (`cache_ipv4_timer`) flushes the cache into one MP_REACH
   UPDATE per attr-bucket.

### 2.2 What is and isn't already shared

| Asset | Shared today? |
|---|---|
| `Arc<BgpAttr>` storage | **Yes** — `BgpAttrStore` interns. |
| Attribute transform computation | No — each peer recomputes from scratch. |
| Outbound policy evaluation | No — each peer runs the same policy independently. |
| Per-attr NLRI grouping for UPDATE packing | No — each peer keeps its own `cache_ipv4`. |
| Adj-RIB-Out membership | No — and cannot be 100% shared because of split-horizon (see §3.2). |
| Encoded UPDATE bytes | No. |

The duplicated work in steps 1–2 is the biggest win. Step 4 is a
secondary win once we hold a per-group pending-cache.

## 3. Design

### 3.1 What defines an update-group

Two peers belong to the same update-group for a given `(afi, safi)` iff
**every** input that drives `route_update_ipv4` and
`route_apply_policy_out` is identical. The signature fields:

| Field on `Peer` | Affects |
|---|---|
| `peer_type` (iBGP/eBGP) | iBGP-iBGP filter, ORIGINATOR_ID, CLUSTER_LIST, AS_PATH prepend gating, NEXT_HOP rewrite gating, default LOCAL_PREF. |
| `reflector_client` | iBGP-iBGP filter override. |
| `local_as` | AS_PATH prepend value. |
| `param.local_addr` (or fallback to `bgp.router_id`) | NEXT_HOP value for eBGP / originated. |
| `policy_list.output.name` | Outbound policy identity. |
| `prefix_set.output.name` | Outbound prefix filter identity. |
| `config.as_override` + `remote_as` (eBGP only) | `as-override` rewrites the peer's remote-AS to `local_as` in the egress AS_PATH; the result depends on `remote_as`, so it joins the key as `as_override_target: Some(remote_as)` (else `None`). |
| `is_afi_safi(afi, safi)` membership | Implicit — only members of the AFI/SAFI participate in that group. |
| `addpath_send` for `(afi, safi)` | Different framing → different group. |

**Negotiated-capability fields** (any capability that changes the
on-wire encoding of UPDATEs must shard the group, otherwise we
cannot share encoded bytes in Phase 3 — and Phase 2 attribute
sharing is already correct since attrs are pre-encoding):

| Capability (RFC) | Affects |
|---|---|
| 4-octet AS Number (RFC 6793) | Without it, AS_PATH uses AS_TRANS (23456) and AS4_PATH is sent separately; bytes differ. |
| Extended Message (RFC 8654) | Caps max UPDATE size at 4096 vs 65535; framing/segmentation diverges. |
| Add-Path (RFC 7911) send mode | NLRI wrapped with path-id; different wire shape. (Already covered above as `addpath_send`.) |
| Extended Next-Hop Encoding (RFC 8950) | NEXT_HOP / MP_REACH next-hop length 4 vs 16 bytes. |
| Multiple Labels (RFC 8277) | Label stack encoding for labeled-unicast / VPN families. |

The signature stores the **negotiated** value (the intersection of
local `cap_send` and remote `cap_recv` recorded on `Peer`), not the
locally configured one.

**Not in the signature** (matches IOS-XR — these don't change
UPDATE wire format, or are informational):

- `rtcv4` (per-peer RT-constrain set) — handled as a per-peer NLRI
  filter applied after the canonical transform, the same way
  split-horizon is. Lifts into a sub-group key in Phase 5 (see §3.2).
- Route Refresh (RFC 2918) / Enhanced Route Refresh (RFC 7313) —
  refresh exchanges are tracked separately (IOS-XR exposes a
  "refresh sub-groups" counter); they don't change steady-state
  UPDATE encoding.
- Graceful Restart (RFC 4724) / LLGR (RFC 9494) — affect EOR
  emission timing and stale-route community attribution on receive,
  per-neighbor state. The sender's encoded UPDATE bytes don't change.
- FQDN / Hostname capability — informational only.
- Software Version capability — informational only.

Knobs that don't yet exist in zebra-rs but will join the signature when
they land: `next-hop-self`, `next-hop-unchanged`, `send-community`
flags (standard / extended / large), `remove-private-as`, outbound
`route-map` (when separate from policy-list), per-peer `update-source`
distinct from `transport.local-address`. (`as-override` landed and is
now modeled as `as_override_target` — see the signature table above.)

**Conservatism rule**: any outbound-affecting setting that the
signature does not yet model forces the peer into a singleton group.
Silent data leak between peers — peer A starts seeing UPDATEs that
peer B's policy was supposed to drop — is the worst-case bug. The
signature carries a `signature_version: u32` constant; whenever a
field is added we bump it, and `show bgp update-group` prints it so
stale cached views are detectable.

### 3.2 Per-peer NLRI variance: split-horizon and RTC

Two peers with identical signatures still produce *route-by-route
different* Adj-RIB-Out membership in two cases:

1. **Split-horizon**: a route originated by peer A is filtered out of
   peer A's UPDATEs (`rib.ident == peer.ident`) but kept for peer B.
2. **Route-Target Constrain** (RFC 4684): for VPNv4 / EVPN, each peer
   advertises a set of RT NLRIs it is willing to receive. The
   advertising side filters per-route by `rtc_match(peer.rtcv4,
   attr.ecom)` — different `rtcv4` sets between peers in the same
   group means different per-peer Adj-RIB-Out content.

Therefore:

- ✅ The **transformed attribute set** (the expensive computation) is
  shareable — it's a function of route attributes plus the signature,
  not of which peer is receiving it.
- ❌ Adj-RIB-Out **membership** cannot be globally shared.
- ✅ The **encoded UPDATE bytes** are shareable for the subset of
  members for which the route passes both split-horizon and RTC.

IOS-XR addresses this with a three-tier hierarchy under each (AFI,
SAFI): **update-group → sub-group → filter-group**. The update-group
is keyed by outbound policy / signature; sub-groups under it
partition members by per-peer NLRI-set divergence (RTC differences,
ORF state, slow-peer convergence cursor); filter-groups refine
further per-peer differences.

zebra-rs collapses this for v1 — share the transform / policy /
encode work at the update-group level, and apply per-peer
split-horizon and RTC as inline filters before each member's queue
(same shape as today's per-peer filtering). Phase 5 introduces a
sub-group layer that materializes RTC- and convergence-driven
partitions explicitly. Filter-groups stay folded into per-peer
filtering until a concrete need surfaces.

### 3.3 Data structures

```rust
// Per-AFI/SAFI: signature → group.
pub struct UpdateGroupSig {
    // Policy / transform identity:
    pub peer_type: PeerType,
    pub reflector_client: bool,
    pub local_as: u32,
    pub local_addr: Option<IpAddr>,
    pub policy_out_name: Option<String>,
    pub prefix_set_out_name: Option<String>,
    pub as_override_target: Option<u32>, // Some(remote_as) iff as-override (eBGP)
    // Negotiated wire-format capabilities (intersection of
    // cap_send and cap_recv on Peer). Anything that changes
    // encoded UPDATE bytes belongs here:
    pub as4_negotiated: bool,            // RFC 6793
    pub extended_message: bool,          // RFC 8654
    pub addpath_send: bool,              // RFC 7911
    pub extended_next_hop: bool,         // RFC 8950
    pub multiple_labels: bool,           // RFC 8277
    pub signature_version: u32,
}
// RTC is intentionally NOT in the signature (matches IOS-XR);
// it's a per-peer NLRI filter applied alongside split-horizon.
// Route Refresh, GR, LLGR, FQDN, Software Version are likewise
// excluded — they don't change UPDATE wire format.
// derive: Hash, Eq, Ord, Clone, Debug

pub struct UpdateGroup {
    pub id: UpdateGroupId,           // "ipv4-unicast.0"
    pub afi_safi: AfiSafi,
    pub sig: UpdateGroupSig,
    pub members: BTreeSet<usize>,    // peer idents
    pub created_at: Instant,
    pub counters: UpdateGroupCounters,

    // Phase 3+: per-group pending cache and timers move here.
    // Phase 5+: sub-groups live here.
}

pub struct UpdateGroupCounters {
    pub policy_runs: u64,
    pub policy_denials: u64,
    pub messages_formatted: u64,
    pub messages_replicated: u64,    // formatted * fan-out (minus split-horizon)
    pub bytes_formatted: u64,
    pub split_horizon_excluded: u64,
    pub last_format_us: Option<u64>,
    pub last_replicate_us: Option<u64>,
}

// On Bgp:
pub update_groups: BTreeMap<AfiSafi, BTreeMap<UpdateGroupSig, UpdateGroup>>,

// On Peer:
pub update_group_id: BTreeMap<AfiSafi, UpdateGroupId>,    // back-reference
```

The double-keyed map `(AfiSafi → Sig → UpdateGroup)` makes
"all-groups-for-this-AFI/SAFI" trivial and keeps lookups O(log n) by
signature equality.

### 3.4 Group lifecycle

| Event | Action |
|---|---|
| Peer transitions to `Established` | Compute signature for each `(afi, safi)` the peer is active in; attach to existing group or create new. |
| Peer leaves `Established` | Detach from all groups. If group becomes empty, drop it. |
| Peer config commit changes any signature field | Recompute signature *at end of commit*; if changed, detach + reattach. Trigger soft-out so the new group's Adj-RIB-Out reflects current state. No session bounce. |
| Peer config commit changes nothing signature-relevant | No-op for grouping. |
| Group's outbound policy edited | Signature is "policy *name*", not body — signature unchanged, group membership stable; attr-cache invalidation handled by existing soft-out path. |
| Capability re-negotiation | Capabilities only change via OPEN, which requires a fresh session. The peer leaves all groups on `Established → ...`, then rejoins on `Idle → ... → Established` with the newly negotiated capability set. No mid-session capability change to handle. |

Recompute deferred to commit-end avoids transient bad groupings
while several leaf-callbacks fire for one logical edit. Same pattern
as the existing policy cascade.

## 4. Phasing

Each phase is a self-contained, reviewable PR.

### Phase 1 — Signature + grouping skeleton (observability only) ✅ shipped (PR #441)

**Scope**

- New module `zebra-rs/src/bgp/update_group.rs`:
  - `UpdateGroupSig`, `UpdateGroup`, `UpdateGroupCounters`,
    `UpdateGroupId`.
  - `pub fn signature_of(peer: &Peer, afi, safi) -> Option<Sig>` —
    returns `None` if peer isn't in this AFI/SAFI or isn't established.
  - `pub fn attach(bgp: &mut Bgp, peer_idx: usize)` /
    `pub fn detach(bgp: &mut Bgp, peer_idx: usize)`.
  - `pub fn rebuild_all(bgp: &mut Bgp)` — full from-scratch rebuild;
    used by tests and as a fallback.
- `Bgp` gains `update_groups`. `Peer` gains `update_group_id`.
- Hook attach/detach into peer state transitions
  (`Established` ↔ anything else).
- New show command (see §5).
- Counters present but mostly stay at zero — no advertise code wired
  through the groups yet.

**Out of scope this phase**

- No change to `route_advertise_to_peers`.
- No shared transforms, no shared encode.

**Acceptance**

- `cargo build`, `cargo clippy --workspace`, `cargo test --workspace`,
  `cargo fmt --all` clean.
- Smoke test: 3 peers, 2 share outbound policy → `show bgp
  update-group` lists 2 groups with correct membership.
- Behaviour-preserving: BDD suite passes unchanged.

**Estimated diff**: ~300–400 lines.

### Phase 2 — Shared attr transform + policy ✅ shipped (PR #442)

**Scope**

- New `route_advertise_to_groups(rd, prefix, selected, src, bgp,
  peers)` replaces the per-peer fan-out call sites:
  - `route_ipv4_update` best-path advertise.
  - `route_soft_out_peer_table`.
  - EVPN equivalents (`route_advertise_evpn_to_peers`).
- For each `UpdateGroup` in the relevant `(afi, safi)`:
  - Pick a canonical member (smallest ident — stable, deterministic).
  - Run `route_update_ipv4` + `route_apply_policy_out` once with the
    canonical peer's view.
  - Intern the result.
  - For each member peer:
    - Apply per-peer split-horizon (`rib.ident == member.ident`).
    - Apply per-peer RT-constrain via `rtc_match(member.rtcv4,
      attr.ecom)` — peers' RTC sets vary independently of the
      update-group signature (matches IOS-XR sub-group semantics).
      v1 applies the per-peer filter inline; Phase 5 lifts this to a
      sub-group structure for efficiency.
    - `member.adj_out.add(...)`; queue into `member.cache_ipv4`.
- `policy_runs` counter increments once per group instead of once per
  member.

**Out of scope this phase**

- Encoded UPDATE bytes are still built per-peer from `cache_ipv4` —
  encode sharing is Phase 3.

**Acceptance**

- BDD pcap goldens: capture UPDATE byte streams against an FRR
  neighbor before and after, byte-diff per (peer, prefix). Must be
  identical.
- New unit tests in `update_group.rs` for signature equality matrix:
  for each signature field, (same, different) pair must produce
  (same group, different group).
- Counters visible: `show bgp update-group` now shows non-zero
  `policy_runs`, `messages_formatted`.

**Estimated diff**: ~500–700 lines (largest phase).

### Phase 3 — Shared encode + per-group pending cache ✅ shipped for IPv4 unicast (PRs #443, #444, #445, #446)

Phase 3 split into four PRs to keep each reviewable:

- **#443 (Phase 3a)**: scaffolding — `UpdateGroup::cache_ipv4*`,
  `Message::FlushUpdateGroupIpv4` + dispatcher, `send_ipv4` /
  `cache_remove_ipv4` / `flush_ipv4` helpers (initially marked
  `#[allow(dead_code)]`).
- **#444 (Phase 3b)**: migrate `route_advertise_to_peers` IPv4
  unicast path to the group cache. Split-horizon Withdraw must
  not clobber other group members' bucket entries.
- **#445 (Phase 3c)**: migrate `route_advertise_to_addpath` /
  `route_withdraw_from_addpath` IPv4 paths. `cache_remove_ipv4`
  gains an `id` parameter for AddPath path-id.
- **#446 (Phase 3d)**: migrate `route_sync_ipv4` /
  `route_soft_out_peer_table` via a new
  `update_group::send_ipv4_direct(peer, entries)` helper —
  per-peer paths bypass the group cache to avoid fan-out
  double-sending. Removes the now-dead `Peer::cache_ipv4*`
  fields, `Event::AdvTimerIpv4Expires`, `start_adv_timer_ipv4`,
  `fsm_adv_timer_ipv4_expires`, etc.

VPNv4 + EVPN remain on per-peer cache. Migrating them is a
follow-up (Phase 3e/3f or rolled into a future cycle).

**Scope**

- `cache_ipv4: HashMap<Arc<BgpAttr>, HashSet<Ipv4Nlri>>` (and vpnv4 /
  evpn variants) move from `Peer` to `UpdateGroup`.
- Adv timer `cache_ipv4_timer` moves to the group.
- Per-peer outgoing send queues remain — they hold pre-built
  `BytesMut` ready for `packet_tx`.
- On flush:
  - Group serialises one MP_REACH/MP_UNREACH UPDATE per attr-bucket
    into a single `BytesMut` per attr.
  - Member peers each get a clone (shallow — `BytesMut` is
    refcounted), pruned for split-horizon.
- For attr-buckets where all NLRIs pass split-horizon for all
  members: members share the exact same byte buffer; ratio
  `replicated / formatted` is `members.len()`.
- For attr-buckets with split-horizon exclusions for some member:
  that member gets a separately-encoded pruned UPDATE; others share
  the canonical one. This is deliberately simple — re-encoding
  partial UPDATEs is cheap relative to policy.

**Acceptance**

- Same byte-level goldens as Phase 2.
- `messages_replicated` and `bytes_formatted` counters meaningful;
  ratio observably > 1 in multi-member groups.

**Estimated diff**: ~400–600 lines.

### Phase 4 — Dynamic regroup on config change ⏳ pending

**Scope**

- At config commit completion, recompute signature for every peer
  whose config touched any signature field (track via a dirty bit
  set during callbacks).
- If signature changed: detach from old group, attach to new (or
  create new singleton). Trigger soft-out for that peer so its new
  group's Adj-RIB-Out reflects current Loc-RIB.
- No session bounce.

**Acceptance**

- BDD: change one peer's outbound policy mid-session; verify the
  peer's group changes in `show bgp update-group`, the session stays
  Established, and the next UPDATE on that peer reflects the new
  policy.

**Estimated diff**: ~150–250 lines.

### Phase 5 — Sub-groups for per-peer NLRI variance ⏳ pending

**Scope**

Within each `UpdateGroup`, partition members into sub-groups along
the dimensions where members' Adj-RIB-Out content legitimately
differs while their signature stays equal:

- **RT-constrain**: members whose `rtcv4` set produces a distinct
  effective NLRI set form a distinct sub-group. Promotes the inline
  per-peer RTC filter from Phase 2 into a structural partition,
  matching IOS-XR's sub-group model.
- **Convergence cursor / slow peer**: a member whose tx is lagging
  forms (or joins) a separate sub-group so it doesn't drag the rest
  of the group's flush rate. Caught-up members fold back into the
  lead sub-group.
- **ORF state** (if/when ORF lands).

Pure runtime split — update-group signature unchanged.

**Acceptance**

- VPNv4 scenario: 4 peers in one update-group, two distinct RTC
  sets; verify two sub-groups, with each carrying its own
  RTC-pruned encoded UPDATE.
- Slow-peer stress: one peer artificially throttled, remaining
  members continue advertising at full rate.
- `show bgp update-group <id>` "Pending sub-groups" section
  populates with reason (RTC / slow / ORF) per sub-group.

**Estimated diff**: ~400–600 lines.

### Phase 6a — BDD coverage for IPv4 unicast 🟡 in progress (PR #447 shipped 6a-1)

**Scope**

End-to-end BDD scenarios that exercise the IPv4 unicast pipeline
shipped through Phase 3d. Goal: verify the group cache is correct
on real sessions, and that the counter ratios reflect the
optimization.

- ✅ **Group formation by policy name** (PR #447, 6a-1): 3
  peers, 2 share outbound policy → assert
  `show bgp update-group` reports exactly 2 groups with both
  group IDs and policy names visible. Detail view surfaces the
  `Negotiated capabilities` block + `Signature version` row.
- ⏳ **Group formation by other signature fields** (6a-?):
  vary one signature field at a time (peer-type, local-as,
  prefix-set name, capability negotiation) and assert the
  regrouping. Likely a single PR adding a few `policy-attach
  variant` scenarios.
- ⏳ **Shared advertise + counter ratio**: with 3 peers in one
  group, originate one prefix → assert each peer receives the
  UPDATE; assert `messages_formatted` increments once per
  attr-bucket and `messages_replicated` increments per
  (UPDATE, member) pair. Replicated/formatted ratio ≈ member
  count. Needs a new `show bgp update-group` JSON-counter
  assertion step.
- ⏳ **Split-horizon**: peer A advertises prefix N to a 3-peer
  group; assert peer A receives no UPDATE for N; peers B and C
  receive the canonical UPDATE; assert
  `split_horizon_excluded` increments.
- ⏳ **Withdraw**: best-path withdrawal triggers a withdraw to
  all non-source members; group cache is cleaned exactly once.
- ⏳ **AddPath**: AddPath-enabled vs non-AddPath peers land in
  different groups; same prefix is encoded once per group.
- ⏳ **Soft-out replay**: targeted at one peer; assert other
  group members do not receive duplicate advertisements (would
  indicate `send_ipv4_direct` is wrongly going through the
  group cache).
- ⏳ **Session join/leave**: peer transitioning to Established
  joins its group atomically; transitioning out detaches; group
  is dropped only on last member leave.

Existing BDD scaffolding in `bdd/tests/features/` is the host;
new feature file is `bgp_update_group_ipv4.feature`. Topology
fixtures use a 3-peer minimum (not 2 — 2 doesn't surface the
source/canonical split-horizon distinction).

**Estimated diff (remaining)**: ~250–400 lines (Gherkin + a
couple of new step implementations for counter assertions).

### Phase 6b — VPNv4 / EVPN BDD + show polish ⏳ pending

**Scope**

- BDD for VPNv4 / EVPN once those families migrate to the group
  cache (separate track — listed at the end of §8).
- `show bgp update-group <id> history` — last N format /
  replicate events with timestamps, prefixes, member counts.
- More counters as needed (queue depths, slow-peer counts after
  Phase 5).
- Documentation: user-facing chapter in `book/src/`.

## 5. `show bgp update-group` design

### 5.1 CLI surface

| Command | Purpose |
|---|---|
| `show bgp update-group` | Summary table — one row per group. |
| `show bgp update-group <id>` | Full detail of one group. |
| `show bgp update-group ipv4 unicast` | Filter by AFI/SAFI. |
| `show bgp update-group neighbor <addr>` | "Which group is this peer in?" — one detail block per AFI/SAFI the peer participates in. |
| `show bgp update-group summary` | Alias for the bare form. |
| `... json` suffix on any of the above | Same data, structured JSON. |

Group IDs are `<afi-safi-tag>.<seq>` — e.g. `ipv4-unicast.0`,
`vpnv4.1`. Mirrors IOS-XR's "0.1" convention. The seq is allocated on
first appearance of a signature and is **not reused** after a group
empties — keeps IDs stable for log correlation.

### 5.2 Summary output (text)

```
BGP update-groups for IPv4 Unicast:

ID                Members  Policy-out         Prefix-out      Type   AS     Updates
ipv4-unicast.0    3        export-to-rrs      —               iBGP   65001  12 / 36
ipv4-unicast.1    2        export-to-edge     deny-internal   eBGP   65001  8 / 16
ipv4-unicast.2    1        —                  —               eBGP   65001  4 / 4

3 groups, 6 members across 6 peers.
```

`Updates` = `formatted / replicated`. Ratio shows the win at a glance.

### 5.3 Detail output (text)

```
Update group ipv4-unicast.0:
  Address family: IPv4 Unicast
  Created: 2026-05-07 14:22:08 (12m38s ago)
  Last sub-group rebuild: 14:22:08

  Signature:
    Peer type:                  iBGP
    Local AS:                   65001
    Local address:              10.0.0.1                  (from Loopback0)
    Route-reflector client:     yes
    Outbound policy-list:       export-to-rrs
    Outbound prefix-set:        —
    Send community:             standard, extended
    Negotiated capabilities:
      4-byte AS:                yes
      Extended message:         yes
      Add-Path send:            disabled
      Extended next-hop enc:    no
      Multiple labels:          no
    Signature version:          1

  Counters:
    Messages formatted:         12
    Messages replicated:        36   (3.0× fan-out)
    Bytes formatted:            1280
    Policy runs:                12
    Policy denials:             0
    Splits-horizon-excluded:    1    (route originator was a member)
    Last format wall:           420µs
    Last replicate wall:        18µs

  Members (3):
    Address           State        Up time      Pfx-sent     In sub-group
    192.0.2.1         Established  12m38s       4            0
    192.0.2.2         Established  12m38s       4            0
    192.0.2.3         Established  12m37s       4            0

  Pending sub-groups: none.
```

Design intent:

- **Signature block** transcribes every field of `UpdateGroupSig`,
  including `signature_version`. Forward-compat: when a new field is
  added the layout doesn't change, just gains a row.
- **Counters** make the optimization observable. Without these, no
  one can tell the feature is even running. `formatted vs replicated`
  + `policy runs` are the headline numbers.
- **Members table** uses the same column shape as `show bgp neighbor`
  summary so cross-referencing is easy.
- **Pending sub-groups** is a placeholder until Phase 5 — always
  "none" before then.

### 5.4 `show bgp update-group neighbor <addr>`

```
Neighbor 192.0.2.1 belongs to:
  ipv4-unicast.0     (3 members, sharing policy export-to-rrs)
  vpnv4.0            (3 members, sharing policy export-vpn-rrs)
```

With `... detail`, prints the full group block for each.

### 5.5 JSON

```json
{
  "afi": "ipv4",
  "safi": "unicast",
  "groups": [
    {
      "id": "ipv4-unicast.0",
      "signature": {
        "peer_type": "ibgp",
        "local_as": 65001,
        "local_addr": "10.0.0.1",
        "reflector_client": true,
        "policy_out": "export-to-rrs",
        "prefix_set_out": null,
        "send_community": ["standard", "extended"],
        "capabilities": {
          "as4_negotiated": true,
          "extended_message": true,
          "addpath_send": false,
          "extended_next_hop": false,
          "multiple_labels": false
        },
        "signature_version": 1
      },
      "counters": {
        "messages_formatted": 12,
        "messages_replicated": 36,
        "bytes_formatted": 1280,
        "policy_runs": 12,
        "policy_denials": 0,
        "split_horizon_excluded": 1,
        "last_format_us": 420,
        "last_replicate_us": 18
      },
      "members": [
        {"address": "192.0.2.1", "state": "Established", "uptime_s": 758, "pfx_sent": 4},
        {"address": "192.0.2.2", "state": "Established", "uptime_s": 758, "pfx_sent": 4},
        {"address": "192.0.2.3", "state": "Established", "uptime_s": 757, "pfx_sent": 4}
      ]
    }
  ]
}
```

JSON keys are stable, lower-snake. Forward-compat with a future
OpenConfig augment if we ever add one.

### 5.6 Implementation seam

- New file `zebra-rs/src/bgp/show_update_group.rs`. `show.rs` is
  already 3.5k lines; do not pile on.
- Snapshot pattern: build a `Vec<UpdateGroupView>` at the top of the
  show handler, then render. Avoids holding a borrow on `bgp.peers`
  while formatting — same pattern `show bgp neighbor` uses.
- Three render functions: `render_summary_text`,
  `render_detail_text`, `render_json`. All read from the same view
  struct.
- Wire into `proto/vtysh.proto` show grammar alongside existing `show
  bgp ...` entries.

### 5.7 Show capability per phase

| Phase | Show capability |
|---|---|
| 1 | Summary, detail, JSON, `neighbor <addr>` lookup. Counters present but mostly zero. |
| 2 | `policy_runs` and `messages_formatted` light up — the 1-per-group savings become visible. |
| 3 | `messages_replicated` and `bytes_formatted` light up. Replication ratio meaningful. |
| 5 | `Pending sub-groups` section populates; per-member `In sub-group` column non-zero. |
| 6 | `show bgp update-group <id> history` — last N events. |

## 6. Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| **Silent data leak** — missed signature field puts two non-equivalent peers in the same group; peer A starts seeing UPDATEs that peer B's policy was supposed to drop. | **Critical** | Conservative signature: any unmodelled outbound knob → singleton. `signature_version` constant, bumped per knob added. Test matrix: for every knob × value pair, assert different signature. Phase 2 byte-level goldens against FRR. |
| **Capability-mismatch wire corruption** — sharing encoded UPDATE bytes between peers with different negotiated capabilities (e.g. 4-octet-AS with non-4-octet-AS) emits malformed bytes to the lesser peer. | **Critical** | All wire-format-affecting capabilities are signature fields (§3.1). Phase 3 encode-sharing strictly within a single group. Test: matrix peer with each capability on/off, assert different signature. |
| **Split-horizon regression** during Phase 2/3 refactor. | High | Goldens. BDD scenarios where a peer originates a route to a multi-member group; verify originator does not receive its own route back. |
| **Slow peer drags group flush rate** before Phase 5. | Medium | Document in v1 as known limitation. Acceptable for homogeneous deployments. Phase 5 closes it. |
| **Transient bad grouping during config commit** as multiple leaves fire. | Medium | Defer signature recompute to commit-end via a dirty-bit set during callbacks. Same pattern as existing policy cascade. |
| **Memory cost of per-group pending caches.** | Low | Net reduction vs per-peer × N caches. Phase 3 should show RSS down, not up. |
| **Group ID drift in logs** when group empties and a new signature later reuses the seq. | Low | IDs are not reused after a group empties — sequence number is monotonic per AFI/SAFI. |

## 7. Out of scope

- **No YANG schema change** — confirmed with the user. Update-groups
  are a runtime optimization, transparent to config.
- **No Adj-RIB-In sharing** — Adj-RIB-In is per-peer by definition;
  out of scope of update-groups.
- **No per-peer policy-deny breakdown in show** — would require policy
  evaluation to record per-peer denial reasons; separate effort.
- **No add-path-send heterogeneous mixing** — peers with different
  add-path send settings are in different groups by signature, full
  stop. No attempt to share within a mixed group.
- **No filter-group tier** — IOS-XR has a third tier (update-group →
  sub-group → filter-group) under each AFI/SAFI. v1 collapses
  filter-group into per-peer inline filtering. Revisit if a concrete
  case demands the extra layer.

## 8. Delivery history & next up

**Shipped (IPv4 unicast):**
- Phase 1 → PR #441 — signature, grouping, `show bgp update-group`.
- Phase 2 → PR #442 — per-call memo cache shares policy/transform
  across same-group peers in `route_advertise_to_peers`.
- Phase 3a → PR #443 — `UpdateGroup` cache + flush scaffolding.
- Phase 3b → PR #444 — `route_advertise_to_peers` IPv4 path on
  group cache. Split-horizon-aware withdrawal.
- Phase 3c → PR #445 — `route_advertise_to_addpath` /
  `route_withdraw_from_addpath` IPv4 paths on group cache.
- Phase 3d → PR #446 — `route_sync_ipv4` /
  `route_soft_out_peer_table` via `send_ipv4_direct` (no group
  fan-out). Removes the per-peer `cache_ipv4*` fields and the
  `Event::AdvTimerIpv4Expires` machinery. **IPv4 unicast Phase 3
  done.**
- Phase 6a-1 → PR #447 — first BDD coverage: 4-namespace
  topology (z1/z2/z3/z4 on br0), three eBGP sessions, group
  formation by outbound policy name verified via existing
  `show command ... should contain` step.

**Next up (in any order):**
- **Phase 6a continuation** — remaining IPv4 unicast BDD
  scenarios (counter ratio, split-horizon, withdraw, AddPath,
  soft-out direct path, session join/leave). May add a new step
  for JSON-counter assertions. ~250-400 lines remaining.
- **Phase 4** — dynamic regroup on config commit. Modest size
  (~150-250 lines). Closes the policy-edit-mid-session use case
  without a session bounce.
- **Phase 5** — sub-groups (RTC / slow-peer / ORF). The bigger
  one (~400-600 lines), unblocks correct VPNv4 RTC handling at
  scale.
- **Phase 6b** — VPNv4 / EVPN BDD + show detail history + docs.
  Lands after the corresponding AFI/SAFI cache migrations.
- **VPNv4 / EVPN cache migration** — apply the Phase 3 pattern to
  the remaining two AFI/SAFIs. Each is ~200-300 lines, structurally
  identical to the IPv4 unicast pass.

## 9. Resolved decisions

1. **No `show ip bgp update-group` form.** The command stays under
   `show bgp ...` only, with explicit AFI/SAFI filter args (e.g.
   `show bgp update-group ipv4 unicast`). Decided 2026-05-07.
2. **VPNv4 / EVPN grouping is per (AFI, SAFI), not per (AFI, SAFI,
   RD).** Confirmed against Cisco IOS-XR: update-groups are keyed by
   address family + outbound policy / signature; RD is route data,
   not a key. Per-peer NLRI variance from RT-constrain (and ORF /
   slow-peer) is handled in the sub-group tier under each
   update-group, which is why §3.2 lifts RTC out of the signature.
   Sources: Cisco 8000 IOS-XR "BGP Link-State Mechanisms and Update
   Groups", "Handling BGP Slow Peers", `Cisco-IOS-XR-ipv4-bgp-oper`
   YANG model. Decided 2026-05-07.
3. **Canonical-member choice is dynamic** (recomputed each
   advertise — `members.iter().next()` on a `BTreeSet`, O(log n) and
   stable). Decided 2026-05-07.
