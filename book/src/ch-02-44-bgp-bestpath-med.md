# Best-Path Selection and MED

The MULTI_EXIT_DISC (MED) is how a neighboring AS says which of its
several links into your AS it would rather you use: lower is better.
Because a MED value only means something to the AS that set it, BGP by
default compares MED **only between paths from the same neighboring
AS** (RFC 4271 §9.1.2.2 (c)), and a path that carries **no MED counts
as MED 0** — the most preferred value.

zebra-rs follows those defaults and offers the two knobs FRR and Cisco
IOS have for changing them.

## Deterministic MED

Comparing MED only within one neighboring AS makes the pairwise
comparison non-transitive. Three paths show it:

| Path | Neighboring AS | MED | BGP Identifier |
|------|----------------|-----|----------------|
| A | 65001 | 10 | 10.0.0.1 |
| B | 65002 | —  | 10.0.0.2 |
| C | 65001 | 5  | 10.0.0.3 |

A beats B (different AS, lower BGP Identifier), C beats A (same AS,
lower MED), and B beats C (different AS, lower BGP Identifier). A
selection that walks the candidates once, keeping the better of each
pair, picks C for the order A, B, C but B for A, C, B — and since a
re-advertised path moves to the end of the list, an unchanged
re-advertisement could move the best path, sending an UPDATE to every
peer and changing the FIB with nothing having changed.

zebra-rs always selects **deterministically**: it finds the best path
within each neighboring AS first (MED applies there), then compares
those winners (MED does not apply between them). The answer — B above —
never depends on the order paths arrived in. This is FRR's
`bgp deterministic-med` (on by default since FRR 7.4) and the
elimination order of RFC 4271 §9.1.2.2; zebra-rs has no knob to turn
it off.

`show bgp <prefix>` reports why the best path won in its `Reason:`
line: the comparison that decided it against the runner-up.

## always-compare-med

```
set router bgp bestpath always-compare-med true
```

Compares MED between **any** two paths, whatever their neighboring AS.
With it, all paths are compared on one scale, so the grouping above no
longer matters. Enable it only when every neighboring AS sets MED
consistently — for example, several links into one provider that
announce through different ASes, or a set of peers you have agreed a
MED scheme with. Otherwise it compares unrelated numbers and picks an
arbitrary exit.

## med missing-as-worst

```
set router bgp bestpath med missing-as-worst true
```

Reads a path that carries no MED as having the **highest** possible MED
(4294967295), so it loses the MED comparison instead of winning it. Use
it when a missing MED means "no preference expressed" rather than "most
preferred".

The knobs are independent. Together, a path without MED loses to any
path with one, even from another neighboring AS.

## Configuration

```yaml
router:
  bgp:
    global:
      as: 65001
      router-id: 10.255.0.1
    bestpath:
      always-compare-med: true
      med:
        missing-as-worst: true
```

Both default to `false`; deleting a leaf restores its default:

```
delete router bgp bestpath always-compare-med true
delete router bgp bestpath med missing-as-worst true
```

A change takes effect at once. zebra-rs re-runs best-path selection
for the routes of the default instance in every address family, and
advertises and installs the prefixes whose best path moved; prefixes
the change does not affect are not re-sent. A per-VRF instance applies
a change at each prefix's next best-path run.

Multipath (`afi-safi <af> maximum-paths`) reads MED under the same rule:
two paths with different MEDs are equal-cost only when MED is not
compared between them.

| Path | Default | Meaning |
|------|---------|---------|
| `/router/bgp/bestpath/always-compare-med` | `false` | Compare MED between paths from different neighboring ASes. |
| `/router/bgp/bestpath/med/missing-as-worst` | `false` | Treat a path without MED as the least preferred. |

## FRR and Cisco equivalents

| zebra-rs | FRR | Cisco IOS / IOS-XE |
|----------|-----|--------------------|
| `bestpath always-compare-med true` | `bgp always-compare-med` | `bgp always-compare-med` |
| `bestpath med missing-as-worst true` | `bgp bestpath med missing-as-worst` | `bgp bestpath med missing-as-worst` |
| always deterministic | `bgp deterministic-med` (default on) | `bgp deterministic-med` (default off) |
