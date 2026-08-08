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
  is logged once at commit, naming the policies on it.

Chain *length* is not limited. A cycle is the only structural condition
that is rejected, and it is detected exactly rather than approximated by
a depth cap. Any acyclic chain, however long, resolves and evaluates.

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
/// Resolved callee. `Arc` both breaks the type cycle (a PolicyList
/// contains PolicyEntry contains PolicyList) and keeps the clone
/// shallow. `None` while `call_name` is `Some` means unresolved or
/// cyclic: the entry denies, per the engine's fail-closed convention
/// for bound-but-unresolved references.
pub call_policy: Option<Arc<PolicyList>>,
```

An indirection is required — without one `PolicyEntry` is infinitely
sized — and it must be `Arc`, not `Box`.

`Box` would deep-clone the callee into every caller. That is fine for a
chain but not for sharing: with A calling both B and C, and both calling
D, D is duplicated twice; nest that and the expansion multiplies. Since
chain length is not capped, the blow-up has no bound either. `Arc` makes
each policy resolved once and referenced by pointer, so the resolved
structure is a DAG whose size is linear in the configuration regardless
of how the calls fan out.

`Arc` also keeps `policy_list_update`'s by-value push cheap: cloning a
`PolicyList` to send to a peer copies one refcount per call edge instead
of a subtree.

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

With `Arc` the embedding cost is one clone per policy per commit, not
per call edge, so it does not grow with chain length or fan-out.

## Resolution

Resolution happens at commit, in `policy/inst.rs`, and is driven by the
call graph rather than by recursive descent from each policy. That is
what removes the need for a depth limit: the structure is analysed once,
exactly, instead of being explored with a budget.

Three steps:

**1. Build the call graph.** Nodes are policy names; there is an edge
`A → B` for every entry of `A` carrying `call B`. Nodes for undefined
callees are recorded but have no outgoing edges.

**2. Find cycles.** A DFS with the usual three-colour marking (white /
grey / black) reports every back edge, and each back edge names a cycle.
Every policy on a cycle is marked unresolvable. Detection is exact and
costs O(V+E) — it does not care how long the chains are.

**3. Resolve in reverse topological order.** With cycles removed the
graph is a DAG, so callees can always be resolved before their callers.
Walk that order once, keeping a side map:

```rust
let mut resolved: BTreeMap<String, Arc<PolicyList>> = BTreeMap::new();
for name in reverse_topological_order {
    let mut list = policy_config[&name].clone();
    policy_entry_sync(&mut list, /* prefix/community/... sets */);
    for entry in list.entry.values_mut() {
        if let Some(callee) = &entry.call_name {
            entry.call_policy = resolved.get(callee).cloned(); // Arc clone
        }
    }
    resolved.insert(name, Arc::new(list));
}
```

Because callees are always already in `resolved`, each policy is
processed exactly once and each call edge costs one `Arc` clone. No
recursion, no visited set threaded through, no depth budget — and the
result is complete for chains of any length.

Policies on a cycle, and callers of an undefined policy, simply find
nothing in `resolved` and keep `call_policy = None`, which denies.

A cycle is logged once at warning level naming the policies on it. It is
operator error rather than a staging artifact, and the symptom
(everything through that policy is denied) is otherwise hard to explain.

## Update propagation

`cascade_indirect_policy_updates` already re-resolves and re-fires
policies when a referenced *set* changes. `call` adds policy→policy
edges, so a change to a policy must reach its callers, their callers, and
so on.

The call graph from the resolution step answers this directly. Reverse
its edges to get callers-of, and from the set of directly-changed
policies take the transitive closure over that reverse graph — every
policy whose resolved form could have changed, computed once:

```
dirty = changed_policies
      ∪ { P : P reaches some changed policy via call edges }
```

Then re-resolve the dirty set in the same reverse topological order and
fire `policy_list_update` for each. Single pass, exact, and independent
of chain length.

This replaces iterating to a fixpoint, which would have needed a bound to
terminate safely. The graph makes the bound unnecessary: a DAG traversal
visits each node once by construction.

`needs_resync` gains `call_name` alongside the existing set predicates,
so a policy that calls a changed policy is pulled in.

## Evaluation

The natural expression is recursive:

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

placed in `policy_list_apply_net` (`bgp/route.rs`) after `entry_matches`
succeeds and before the `match entry.action` block.

With no depth limit, recursion depth is bounded only by the
configuration: the resolved graph is acyclic, so depth cannot exceed the
number of distinct policies. That is a real bound but an operator-chosen
one, and this runs on the per-prefix hot path where the stack is shared
with the rest of the update pipeline.

**Prefer an explicit stack.** Keep a `Vec` of resume points — the policy
being evaluated and the entry iterator position — push on `call`, pop
when a callee finishes, and carry `decision` across. It is a modest
amount of extra code and it makes evaluation depth a heap concern rather
than a stack one, so an unusually deep configuration degrades in
allocation rather than aborting the process.

Recursion is acceptable for a first implementation if the iterative form
proves awkward, but then the depth-vs-stack question should be measured
rather than assumed, and the reasoning recorded next to the code.

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
* a long acyclic chain (say 64 deep) resolves and evaluates correctly —
  the guard against a depth limit creeping back in
* a diamond (A calls B and C, both call D) resolves D once and shares it,
  rather than duplicating it per caller

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

Commit-time cost is one clone plus one `policy_entry_sync` per policy,
independent of how the calls fan out, because resolution walks the DAG
once and shares callees through `Arc`. The pathological case that would
have mattered — a diamond or a deep chain multiplying deep clones — is
what the `Arc` choice removes.

Evaluation depth is bounded by the number of policies rather than by a
constant. The explicit-stack form above is what keeps that from being a
stack-safety question.
