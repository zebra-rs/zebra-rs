# `call` — policy chaining in the routing-policy engine

Status: design proposal
Motivation: SONiC port (`docker-fpm-zebra-rs`), BGP allow-list feature

## Why

SONiC's `bgpcfgd` builds its peer-inbound policy out of a call chain:

```
route-map FROM_BGP_PEER_V4 permit 10
  call ALLOW_LIST_DEPLOYMENT_ID_0_V4
  on-match next
route-map FROM_BGP_PEER_V4 permit 11
  match community allow_list_default_community
  ...
```

The called map is not static template output. `managers_allow_list.py`
owns it at runtime: it adds and removes entries as CONFIG_DB's
`BGP_ALLOWED_PREFIXES` changes, allocating sequence numbers *inside* that
map. So the chain cannot be flattened into the caller at
template-render time — every allow-list update would have to rewrite and
renumber the caller.

`on-match next` needs nothing: it is already `action next`
(`PolicyAction::Next`). `call` is the missing piece. `set tag` is also
required by the same feature but is independent and much smaller (a plain
u32 route attribute); it is out of scope here.

Without `call`, the allow-list feature cannot be expressed at all, and
the SONiC template refuses it rather than emitting a policy that silently
drops different routes.

## Semantics

Matching FRR, which is what the SONiC templates were written against:

1. An entry's `call <policy>` runs **after** the entry's own `match`
   clauses have matched, and **before** its terminal action is applied.
2. If the called policy **denies**, the calling policy denies
   immediately. Evaluation stops; the route is rejected.
3. If the called policy **permits**, evaluation continues with the
   calling entry's own `set` clauses and terminal action.
4. `set` clauses applied inside the called policy are **kept** — the
   callee mutates the same working attribute set. This is what makes
   `call` useful rather than a glorified match.

Note the asymmetry: a callee's `permit` does *not* terminate the caller.
It only reports "not denied".

### Unresolved and cyclic references

zebra-rs's established convention is that a bound-but-unresolved
reference is **deny-all** — see `PolicyType::PrefixSetIn` and
`PolicyListIn` in `policy/inst.rs`, where an absent set or list is
delivered as `None` precisely so the subscriber fails closed rather than
silently passing traffic it was told to filter.

`call` follows that convention:

* `call NAME` where `NAME` is not defined → the entry **denies**.
* `call` participating in a cycle → the entry **denies**, and the cycle
  is logged once at commit.

Fail-closed is the right default for a routing filter: a policy that was
asked to consult a filter it cannot find should not conclude "permit".
This does differ from FRR in the undefined-map case, and that difference
belongs in the SONiC porting notes rather than being papered over.

## Data model

`PolicyEntry` already carries every reference twice — the configured
name and the resolved object:

```rust
pub prefix_set_name: Option<String>,
pub prefix_set: Option<PrefixSet>,
```

`call` follows the same shape:

```rust
/// `call <policy>` — run another policy from this entry.
pub call_name: Option<String>,
/// Resolved callee. `Box` breaks the type cycle (a PolicyList
/// contains PolicyEntry contains PolicyList). `None` while
/// `call_name` is `Some` means unresolved or cyclic: the entry
/// denies, per the engine's fail-closed convention for bound-but-
/// unresolved references.
pub call_policy: Option<Box<PolicyList>>,
```

Boxing is required: without it `PolicyEntry` becomes infinitely sized.

### Why embed rather than look up at evaluation time

Policies are distributed **by value**. `policy_list_update(name, list)`
pushes a *clone* to each registered consumer, and a BGP peer holds its
own `Option<PolicyList>` per direction. There is no registry reachable
from `policy_list_apply_net`.

Introducing one — threading an `Arc<PolicyRegistry>` through every apply
call site and keeping it coherent with the per-peer copies — is a much
larger change than this feature warrants, and it would add a shared
structure to the per-prefix hot path. Embedding keeps `call` inside the
existing resolve-and-push model, and keeps evaluation allocation-free.

The cost is clone depth on config commit, bounded by the depth cap below.

## Resolution

Extend `policy_entry_sync` (`policy/policy_list.rs`), which already
resolves `prefix_set_name` → `prefix_set` and friends, to resolve
`call_name` → `call_policy` from the policy config map.

Resolution is recursive and must be bounded:

```
MAX_CALL_DEPTH = 8
```

Resolve with an explicit visited set along the current path:

* If the callee is not in the config map → leave `call_policy = None`
  (entry denies), log at debug — the name may simply be defined later,
  and the watch mechanism will re-resolve.
* If the callee is already on the current path → cycle. Leave
  `call_policy = None`, log a **warning** naming the cycle. A cycle is
  operator error, not a staging artifact, and deserves to be visible.
* If depth exceeds `MAX_CALL_DEPTH` → same as a cycle.

Eight is chosen as a limit no legitimate configuration approaches (SONiC
uses one level) while keeping worst-case commit-time clone depth
trivial.

## Update propagation

`cascade_indirect_policy_updates` already re-resolves and re-fires
policies when a referenced *set* changes. `call` adds policy→policy
edges, which makes propagation transitive: if C changes and B calls C
and A calls B, then A's embedded copy is stale too.

Extend the cascade in two steps:

1. Add `call_name` to the `needs_resync` predicate, so a policy that
   calls a changed policy re-resolves.
2. Iterate the cascade to a fixpoint (bounded by `MAX_CALL_DEPTH`
   passes), because step 1 makes *A* newly-changed only after *B* has
   been re-resolved. A single pass would leave A holding a stale copy of
   B — a silent correctness bug, and the most likely defect in this
   feature.

An alternative worth considering if the fixpoint proves awkward:
maintain a reverse index (callee → callers) built at commit, and walk it
in dependency order. That is more code but makes the transitive step
explicit rather than emergent.

## Evaluation

In `policy_list_apply_net` (`bgp/route.rs`), after `entry_matches`
succeeds and before the `match entry.action` block:

```rust
if entry.call_name.is_some() {
    let Some(callee) = &entry.call_policy else {
        return None;                       // unresolved or cyclic: deny
    };
    match policy_list_apply_net(callee, prefix, decision.attr, decision.weight, local_addr) {
        None => return None,               // callee denied: caller denies
        Some(d) => decision = d,           // keep the callee's set clauses
    }
}
```

The recursion is bounded at resolve time, so no runtime depth counter is
needed — a resolved `call_policy` cannot be deeper than
`MAX_CALL_DEPTH`. That invariant should be asserted in the resolver, not
assumed here.

Cost is confined to entries that actually carry a `call`; every other
policy evaluation is unchanged.

## Configuration

YANG, alongside the existing entry leaves in `config.yang`:

```yang
leaf "call" {
  ext:help "Run another policy from this entry";
  type string;
  description
    "Name of a policy to evaluate when this entry matches. If the
     called policy denies, this policy denies. If it permits,
     evaluation continues with this entry's set clauses and action.
     A plain string rather than a leafref, matching prefix-set and
     community-set references, so a policy may be configured before
     the policy it calls.";
}
```

A plain string, not a leafref: the engine deliberately allows staged
references so config can be applied in any order. That is also why cycle
detection has to be a runtime/commit-time check rather than a schema
constraint.

CLI shape follows the existing entry leaves:

```
set policy FROM_BGP_PEER_V4 entry 10 call ALLOW_LIST_DEPLOYMENT_ID_0_V4
set policy FROM_BGP_PEER_V4 entry 10 action next
```

## Show output

`show policy` should render the call and its resolution state, since
"unresolved" is the difference between permit and deny:

```
policy FROM_BGP_PEER_V4
  entry 10 action next
    call ALLOW_LIST_DEPLOYMENT_ID_0_V4
```

and, when unresolved:

```
    call ALLOW_LIST_DEPLOYMENT_ID_0_V4 [unresolved: denies]
```

An operator debugging a filter that drops everything should be able to
see why from `show`, not from the log.

## Tests

Unit, in `policy_list.rs` alongside the existing entry tests:

* callee permits → caller continues; callee's `set` clauses are visible
  in the result
* callee denies → caller denies, and the caller's own `set` clauses are
  **not** applied
* `call` + `action next` → callee runs, then evaluation falls through to
  the next entry
* unresolved `call` → deny
* direct cycle (A→A) and indirect cycle (A→B→A) → deny, resolver logs
* depth > MAX_CALL_DEPTH → deny

Resolution, in `policy/inst.rs`:

* editing a callee re-fires every caller (the transitive cascade) —
  specifically A→B→C with C edited must update A
* defining a previously-missing callee flips the caller from deny to
  permit without a peer bounce

Integration (BDD), the behaviour that motivates the feature:

* a route denied by the callee is absent from the peer's Adj-RIB-In
* a route permitted by the callee carries the communities the callee set

## Scope

Not included, deliberately:

* `set tag` — needed by the same SONiC feature, unrelated mechanism,
  belongs in its own change.
* `call` from the table-map path — the SONiC use is peer-inbound policy;
  extending it later is mechanical once the resolver handles it.

## Risks

The transitive cascade is the part most likely to be subtly wrong, and
its failure mode is silent: a stale embedded copy means a policy keeps
filtering on an old version of a called map, with nothing in the log. The
A→B→C test above is the guard, and is worth writing before the
implementation rather than after.

Commit-time cost grows with call depth because each level deep-clones
the callee. At depth 1 (the SONiC case) this is one extra clone per
caller per commit, which is not worth optimising for; if deeper chains
ever appear in practice, `Arc<PolicyList>` instead of `Box` would make
the clone shallow at the cost of making mutation-on-resolve explicit.
