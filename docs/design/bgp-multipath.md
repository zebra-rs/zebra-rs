# BGP multipath (`maximum-paths`)

Status: design proposal
Motivation: SONiC port — the largest functional gap on the list

## Why

A SONiC T0 or T1 has several equal-cost upstream peers and expects to
load-share across all of them. Its templates say so:

```
address-family ipv4
  maximum-paths 514
```

zebra-rs installs **one** of those paths. Everything else is dropped on
the floor at FIB-install time, so a leaf with four uplinks forwards all
of its traffic over one of them. Nothing errors; the session count, the
route count, and `show bgp` all look correct.

This is not a missing config leaf over working machinery — the machinery
is absent:

* `BgpTable::select_best_path` (`bgp/route.rs`) computes a single
  `best_index` by pairwise `is_better`, sets `best_path = true` on it and
  `Reason::NotSelected` on every other candidate, and pushes exactly one
  `BgpRib` into the returned `Vec`. The `Vec` return type and
  `fib_install_v4(…, selected: &[BgpRib])` look multipath-shaped, but the
  comment on `fib_install_v4` states the invariant plainly: "at most one
  `BgpRib` after best-path selection".
* `make_bgp_rib_entry_v4` takes `best: &BgpRib` — singular — and builds
  one `rib::Nexthop::Uni`.
* The `= multipath` status code in `show` output
  (`bgp/show.rs:379`) has nothing computing it.
* The only `multipath` in `src/bgp/` is on *redistribute*, which is a
  different question (whether to redistribute a route that is multipath),
  not BGP path selection.

## What already exists

Two thirds of the plumbing is in place, which is what makes this
tractable:

* **The RIB can represent it.** `rib::Nexthop::Multi(NexthopMulti {
  metric, nexthops: Vec<NexthopUni>, gid })` exists and is exercised
  today: `build_vpn_fib_entry` builds `Uni` for one transport egress and
  `Multi` for several. So this is a shape the FIB layer already accepts.
* **The southbound can carry it.** The FPM encoder emits a flat
  `RTA_GATEWAY` + `RTA_OIF` for one leg and `RTA_MULTIPATH | NLA_F_NESTED`
  for two or more, verified byte-identical against FRR captures. Nothing
  below BGP needs to change.

What is missing is confined to path *selection* and the config surface.

## Semantics

### Which paths are multipath candidates

Follow the bestpath ladder in `is_better` and cut it at the point where
the remaining comparisons are pure tie-breakers. In order, that ladder is:

| # | Comparison | Multipath |
|---|---|---|
| 1 | next-hop reachable | must match |
| 2 | not stale (LLGR) | must match |
| 3 | weight | must match |
| 4 | local-pref | must match |
| 5 | locally originated | must match |
| 6 | AS-path length | must match |
| 7 | origin | must match |
| 8 | MED (same neighbouring AS only) | must match |
| 9 | eBGP vs iBGP (`route_type_rank`) | must match |
| — | **cut here** | |
| 10 | BGP Identifier / ORIGINATOR_ID | ignored |
| 11 | peer slot (`ident`) | ignored |
| 12 | AddPath path-id (`remote_id`) | ignored |

Steps 10–12 exist only to pick *one* winner deterministically among
otherwise-equal paths. Disqualifying on them is precisely wrong: they are
what makes a set of equal paths a set.

This matches FRR, and it is why a candidate set is best computed as "ties
with the winner through step 9" rather than by re-running `is_better`,
which never reports equality — it returns `(false, NotSelected)` both for
"worse" and for "identical".

### `multipath-relax`, and a default that needs deciding

FRR's default requires eBGP multipath candidates to have the **same
neighbouring AS**, not merely the same AS-path length;
`bgp bestpath as-path multipath-relax` drops that to length-only.

zebra-rs's ladder compares `as_path_len` and never compares AS-path
content. So a naive implementation gets `multipath-relax` behaviour
**by default** — the looser of the two — and the strict mode would be the
thing needing new code.

That asymmetry should be resolved deliberately rather than by accident.
Recommendation: implement the strict comparison (same neighbouring AS)
as the default so behaviour matches FRR, and let `multipath-relax`
disable it. A device that silently load-shares across two different
upstream ASes when its operator did not ask for it is a routing-policy
surprise, and SONiC's own templates make `multipath_relax` an explicit
opt-in via `constants.bgp.multipath_relax.enabled`.

Note that `neighboring_as()` already exists on the attr — it is used for
the MED comparison at step 8.

### Limit and ordering

`maximum-paths N` caps the installed set. The bestpath always occupies a
slot and must always be present, so the cap applies to the candidate set
*after* the winner is placed. Order the remainder by the same tie-break
ladder (steps 10–12) so the installed set is deterministic across
restarts and across peers — an ECMP set that reshuffles on every
recompute produces flow reordering with no config change.

Separate limits for eBGP and iBGP are FRR's model (`maximum-paths` and
`maximum-paths ibgp`). SONiC sets only the eBGP form per address family.
Model both, defaulting iBGP to the same value, but only the eBGP path
needs to work for the port.

## Data model

`BgpRib` carries `best_path: bool` and `best_reason: Reason`. Add:

```rust
/// This path is installed alongside the bestpath as part of an ECMP
/// set. Mutually inclusive with `best_path` on the winner itself —
/// the bestpath is always a member of its own multipath set — so
/// `show` renders the winner as `>` and the rest as `=`.
pub multipath: bool,
```

`select_best_path` already resets per-candidate flags on every run, so
`multipath` joins that reset and cannot go stale.

Return the whole set from `select_best_path`, which finally makes the
`Vec<BgpRib>` return type honest, and delete the "at most one" comment on
`fib_install_v4`.

## Selection

In `select_best_path`, after the winner is chosen and the NHT gate has
passed:

```rust
let mut set = vec![best.clone()];
if max_paths > 1 {
    for cand in cands.iter().filter(|c| !c.best_path) {
        if multipath_eligible(cand, &best, relax) && set.len() < max_paths {
            cand.multipath = true;
            set.push(cand.clone());
        }
    }
}
```

with `multipath_eligible` comparing exactly steps 1–9 above, factored out
of `is_better` so the two cannot drift — the failure mode of a second,
hand-copied ladder is that a new tie-break lands in one and not the
other, and the symptom is an ECMP set that silently includes a path it
should not.

**Deduplicate by resolved next-hop.** Two paths from different peers can
carry the same next-hop; installing it twice would double its share of
the hash. This is a real case with route reflectors.

## FIB install

`make_bgp_rib_entry_v4` / `_v6` take `&[BgpRib]` instead of `&BgpRib` and
mirror what `build_vpn_fib_entry` already does — one leg builds
`Nexthop::Uni`, two or more build `Nexthop::Multi`. Keeping the one-leg
case as `Uni` matters beyond tidiness: the FPM encoder emits a flat
`RTA_GATEWAY`/`RTA_OIF` for `Uni` and a nested `RTA_MULTIPATH` for
`Multi`, and the golden traces pin the flat form for single-nexthop
routes.

`weight` on each `NexthopUni` stays 1 — UCMP is a separate feature
(`NexthopMulti` carries weights, but nothing in BGP sets them yet).

The other install paths — VPN, SRv6, VXLAN, inherited-seg6 — keep taking
the winner alone. They resolve *transport* ECMP separately and already
build `Multi` from it; layering BGP-path ECMP on top of transport ECMP is
a distinct problem and out of scope here.

## Configuration

Per address family, mirroring where FRR puts it:

```yang
list afi-safi {
  leaf maximum-paths {
    ext:help "Maximum number of equal-cost paths to install";
    type uint32 { range "1..max"; }
    description
      "Number of equal-cost BGP paths installed for one prefix. 1
       disables multipath. The bestpath always occupies one slot.";
  }
  container bestpath {
    container as-path {
      leaf multipath-relax {
        ext:help "Treat paths with equal AS-path length as equal-cost";
        type boolean;
        description
          "When true, eBGP paths qualify as multipath on AS-path
           LENGTH alone. When false (default, matching FRR) they must
           also share the same neighbouring AS.";
      }
    }
  }
}
```

CLI:

```
set router bgp afi-safi ipv4 maximum-paths 64
set router bgp afi-safi ipv4 bestpath as-path multipath-relax true
```

Both belong at `/router/bgp/afi-safi/…`, which already exists and already
carries `table-map`, `network` and `redistribute`. `/router/bgp/global`
stays as it is — this is per-family state, and FRR places it inside
`address-family` too.

Changing either value must re-run best-path for the family, not wait for
the next update: lowering `maximum-paths` has to withdraw the paths that
no longer fit.

## Show

The status-code legend already promises `= multipath`, so
`show bgp ipv4` should start honouring it: `>` for the bestpath, `=` for
the other installed members, blank for candidates that lost.

`show bgp ipv4 <prefix>` should say why a path is not a member, since
"equal-cost to my eye but not installed" is the question an operator
actually arrives with. The existing `Reason` enum gives the bestpath
comparison a vocabulary; multipath eligibility needs the same, and the
answer is usually step 8 (MED) or step 9 (eBGP vs iBGP).

## Tests

Unit, beside the existing best-path tests:

* two eBGP paths equal through step 9 → both installed, `Multi` built,
  winner keeps `best_path`, other gets `multipath`
* differing local-pref / AS-path length / MED / origin → one path only
* differing only in router-id → **both** installed (the regression this
  feature is most likely to get wrong)
* same next-hop from two peers → deduplicated to one leg
* `maximum-paths 2` with three eligible paths → exactly two, and the
  bestpath is one of them
* `maximum-paths 1` → identical behaviour to today
* strict vs relax: two paths, equal length, different neighbouring AS →
  one path by default, two with `multipath-relax`
* eBGP and iBGP paths otherwise equal → not mixed
* lowering `maximum-paths` at runtime withdraws the surplus legs

FIB shape, against the encoder's golden traces:

* one leg → flat `RTA_GATEWAY` + `RTA_OIF`, byte-identical to today
* two legs → `RTA_MULTIPATH | NLA_F_NESTED`, matching the FRR capture
  already in `golden/basic-nhg.fpm`

Integration (BDD): a topology with two equal upstreams; assert both
next-hops reach APPL_DB for the prefix, and that withdrawing one leaves
the other installed without a transient withdraw of the prefix itself.

## Risks

**The tie-break cut is the whole feature.** Cutting too early
(disqualifying on router-id) yields no multipath at all and looks like
the feature does not work. Cutting too late (ignoring MED or peer type)
yields ECMP across paths that are not equal-cost, which looks like it
works and misroutes traffic. Factoring the shared ladder out of
`is_better` rather than copying it is what keeps the two honest.

**The default relax question above is a behaviour change waiting to
happen.** Because zebra-rs never compares AS-path content, implementing
"whatever the ladder already does" silently ships `multipath-relax`
semantics to everyone. Whichever default is chosen, it should be chosen
on purpose and stated in the YANG description.

**Flow reordering on recompute.** If the installed set's *order* is not
deterministic, an unrelated update can reshuffle the ECMP legs and move
live flows between links. Ordering by the existing tie-break ladder is
what avoids it.

## Scope

Not included, deliberately:

* **UCMP / weighted ECMP.** `NexthopMulti` carries per-leg weights and
  SONiC has a WCMP knob, but link-bandwidth-driven weighting is its own
  feature.
* **BGP-path ECMP layered over transport ECMP** for VPN/SRv6/EVPN
  installs — those paths keep installing the winner alone.
* **`maximum-paths ibgp` as a distinct limit** — modelled, defaulted to
  the eBGP value, not separately exercised by the SONiC port.
