//! Parallel TI-LFA computation (design:
//! `docs/design/isis-tilfa-parallel-spf.md`).
//!
//! The per-destination TI-LFA work decomposes into jobs with two
//! exact identities (verified by the PR-A oracle tests in `calc.rs`):
//!
//! * **I1** — the P-space SPF is byte-identical to the primary
//!   reachability SPF; only the per-`x` filter differs. No mode here
//!   runs it: every mode derives P-space via
//!   [`p_space_from_spf`] over the caller's primary SPF result.
//! * **I2** — the PC-path (x-excluded) SPF depends on the protected
//!   node `x` only, not the destination; destinations behind the same
//!   first hop can share one tree.
//!
//! What remains per destination is the Q-space reverse SPF plus the
//! SPF-free reduce ([`repair_from_parts`]). The
//! [`TilfaComputeMode`]s differ in how those jobs are scheduled on
//! the rayon global pool — see each variant. All modes return the
//! same map; equivalence against the [`super::calc::tilfa`] reference
//! is pinned by the tests at the bottom.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Duration, Instant};

use rayon::prelude::*;

use super::calc::{
    Graph, Path, RepairPath, SpfDirect, SpfOpt, p_space_from_spf, q_space_vertices,
    repair_from_parts, spf_calc,
};

/// How the per-destination TI-LFA computation is executed.
/// Operator-facing via `fast-reroute ti-lfa compute-mode` (plus
/// `compute-shards` for [`Self::Sharding`]).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TilfaComputeMode {
    /// Sequential loop on the SPF worker thread; rayon is never
    /// touched. 2 SPFs per target.
    #[default]
    Serial,
    /// One parallel task per destination running the serial loop's
    /// body — 2 SPFs per task, no shared SPF work between tasks.
    Conservative,
    /// SPF-granularity map-reduce: phase A computes the PC tree per
    /// distinct protected node in parallel, phase B runs each
    /// target's Q SPF with the reduce fused in. Full PC dedup
    /// (`N + |X|` SPFs), fastest wall clock.
    Aggressive,
    /// Targets grouped by protected node and LPT-bin-packed into at
    /// most this many parallel shards — the operator's hard upper
    /// bound on TI-LFA parallelism. Each shard computes a group's PC
    /// tree once, so the SPF count matches Aggressive.
    Sharding(u16),
}

impl std::fmt::Display for TilfaComputeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TilfaComputeMode::Serial => write!(f, "serial"),
            TilfaComputeMode::Conservative => write!(f, "conservative"),
            TilfaComputeMode::Aggressive => write!(f, "aggressive"),
            TilfaComputeMode::Sharding(k) => write!(f, "sharding({k})"),
        }
    }
}

/// YANG mirror of the `fast-reroute/ti-lfa/compute-mode` leaf
/// (payload-free — the sharding count lives in the sibling
/// `compute-shards` leaf; [`Self::with_shards`] joins them into the
/// scheduler-facing [`TilfaComputeMode`]). Shared by the IS-IS and
/// OSPF config layers, which carry the same two leaves.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, strum_macros::EnumString, strum_macros::Display,
)]
pub enum TilfaComputeModeConfig {
    #[default]
    #[strum(serialize = "serial")]
    Serial,
    #[strum(serialize = "conservative")]
    Conservative,
    #[strum(serialize = "aggressive")]
    Aggressive,
    #[strum(serialize = "sharding")]
    Sharding,
}

impl TilfaComputeModeConfig {
    /// Combine with the `compute-shards` leaf value into the
    /// scheduler-facing mode (the count only matters for sharding).
    pub fn with_shards(self, shards: u16) -> TilfaComputeMode {
        match self {
            TilfaComputeModeConfig::Serial => TilfaComputeMode::Serial,
            TilfaComputeModeConfig::Conservative => TilfaComputeMode::Conservative,
            TilfaComputeModeConfig::Aggressive => TilfaComputeMode::Aggressive,
            TilfaComputeModeConfig::Sharding => TilfaComputeMode::Sharding(shards),
        }
    }
}

/// One TI-LFA computation target, as planned by the protocol caller
/// (IS-IS: `isis::tilfa::tilfa_targets`): a destination vertex and
/// the protected vertex `x` (its primary first-hop node).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TilfaTarget {
    pub d: usize,
    pub x: usize,
}

/// Per-run TI-LFA compute telemetry, surfaced by `show isis spf`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TilfaStats {
    /// Scheduling mode this run executed under.
    pub mode: TilfaComputeMode,
    /// Protected destinations computed this run.
    pub targets: usize,
    /// Q-space reverse SPFs run (one per target).
    pub q_spf: usize,
    /// PC-path (x-excluded) SPFs run.
    pub pc_spf: usize,
    /// PC SPFs avoided by sharing one tree across the destinations
    /// behind the same protected node (`targets - distinct x`).
    pub pc_deduped: usize,
    /// Maximum worker parallelism for the run (1 = sequential).
    pub width: usize,
    /// Wall-clock time of the whole TI-LFA computation.
    pub duration: Duration,
}

impl TilfaStats {
    /// Fold another run's stats in (legacy + MT2 topologies run
    /// sequentially within one SPF cycle, so durations add and the
    /// width is whichever run fanned out wider).
    pub fn merge(self, other: TilfaStats) -> TilfaStats {
        TilfaStats {
            mode: self.mode,
            targets: self.targets + other.targets,
            q_spf: self.q_spf + other.q_spf,
            pc_spf: self.pc_spf + other.pc_spf,
            pc_deduped: self.pc_deduped + other.pc_deduped,
            width: self.width.max(other.width),
            duration: self.duration + other.duration,
        }
    }
}

/// An x-group: one protected node and the targets behind it — the
/// PC-SPF sharing unit for the sharding mode.
type XGroup = (usize, Vec<TilfaTarget>);

/// Compute TI-LFA repair paths for `targets`, scheduling the work per
/// `mode`. `spf_result` must be the primary full-path SPF tree rooted
/// at `source` on this `graph` (it seeds the P-space filters — I1).
/// Destinations whose repair list comes back empty are omitted from
/// the map, matching the historical per-destination loop.
pub fn tilfa_compute(
    graph: &Graph,
    source: usize,
    spf_result: &BTreeMap<usize, Path>,
    targets: &[TilfaTarget],
    mode: TilfaComputeMode,
) -> (BTreeMap<usize, Vec<RepairPath>>, TilfaStats) {
    let start = Instant::now();
    if targets.is_empty() {
        let stats = TilfaStats {
            mode,
            width: 1,
            duration: start.elapsed(),
            ..TilfaStats::default()
        };
        return (BTreeMap::new(), stats);
    }

    // P-space per distinct protected node — filters over the primary
    // SPF result, no SPF (I1). Cheap; shared read-only by every mode.
    let p_sets: HashMap<usize, BTreeSet<usize>> = targets
        .iter()
        .map(|t| t.x)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|x| (x, p_space_from_spf(spf_result, source, &[x])))
        .collect();

    let (result, mut stats) = match mode {
        TilfaComputeMode::Serial => run_per_target(graph, source, targets, &p_sets, false),
        TilfaComputeMode::Conservative => run_per_target(graph, source, targets, &p_sets, true),
        TilfaComputeMode::Aggressive => run_aggressive(graph, source, targets, &p_sets),
        TilfaComputeMode::Sharding(k) => run_sharded(graph, source, targets, &p_sets, k),
    };
    stats.mode = mode;
    stats.targets = targets.len();
    stats.duration = start.elapsed();
    (result, stats)
}

/// One target's computation: Q-space reverse SPF + PC-path SPF +
/// reduce. The body shared by the serial and conservative modes (the
/// PC tree is *recomputed* per target here — that is conservative's
/// no-shared-state simplicity tradeoff; aggressive/sharding share it
/// per `x` instead).
fn per_target(
    graph: &Graph,
    source: usize,
    p: &BTreeSet<usize>,
    t: TilfaTarget,
) -> (usize, Vec<RepairPath>) {
    let q = q_space_vertices(graph, t.d, &[t.x]);
    let pc = spf_calc(
        graph,
        source,
        &[t.x],
        &SpfOpt::full_path(),
        &SpfDirect::Normal,
    );
    let repairs = pc
        .get(&t.d)
        .map(|dp| repair_from_parts(graph, source, p, &q, &dp.paths, &dp.first_hop_links))
        .unwrap_or_default();
    (t.d, repairs)
}

fn run_per_target(
    graph: &Graph,
    source: usize,
    targets: &[TilfaTarget],
    p_sets: &HashMap<usize, BTreeSet<usize>>,
    parallel: bool,
) -> (BTreeMap<usize, Vec<RepairPath>>, TilfaStats) {
    let pairs: Vec<(usize, Vec<RepairPath>)> = if parallel {
        targets
            .par_iter()
            .map(|t| per_target(graph, source, &p_sets[&t.x], *t))
            .collect()
    } else {
        targets
            .iter()
            .map(|t| per_target(graph, source, &p_sets[&t.x], *t))
            .collect()
    };
    let stats = TilfaStats {
        q_spf: targets.len(),
        pc_spf: targets.len(),
        pc_deduped: 0,
        width: if parallel {
            rayon::current_num_threads()
        } else {
            1
        },
        ..TilfaStats::default()
    };
    (collect_nonempty(pairs), stats)
}

fn run_aggressive(
    graph: &Graph,
    source: usize,
    targets: &[TilfaTarget],
    p_sets: &HashMap<usize, BTreeSet<usize>>,
) -> (BTreeMap<usize, Vec<RepairPath>>, TilfaStats) {
    // Phase A: one x-excluded PC SPF per distinct protected node (I2).
    let xs: Vec<usize> = p_sets.keys().copied().collect();
    let pc_trees: HashMap<usize, BTreeMap<usize, Path>> = xs
        .par_iter()
        .map(|&x| {
            (
                x,
                spf_calc(
                    graph,
                    source,
                    &[x],
                    &SpfOpt::full_path(),
                    &SpfDirect::Normal,
                ),
            )
        })
        .collect();

    // Phase B: per-target Q SPF with the reduce fused in, so no
    // N-sized intermediate barrier — each task drops its Q set on
    // emit.
    let pairs: Vec<(usize, Vec<RepairPath>)> = targets
        .par_iter()
        .map(|t| {
            let q = q_space_vertices(graph, t.d, &[t.x]);
            let repairs = pc_trees[&t.x]
                .get(&t.d)
                .map(|dp| {
                    repair_from_parts(
                        graph,
                        source,
                        &p_sets[&t.x],
                        &q,
                        &dp.paths,
                        &dp.first_hop_links,
                    )
                })
                .unwrap_or_default();
            (t.d, repairs)
        })
        .collect();

    let stats = TilfaStats {
        q_spf: targets.len(),
        pc_spf: xs.len(),
        pc_deduped: targets.len() - xs.len(),
        width: rayon::current_num_threads(),
        ..TilfaStats::default()
    };
    (collect_nonempty(pairs), stats)
}

fn run_sharded(
    graph: &Graph,
    source: usize,
    targets: &[TilfaTarget],
    p_sets: &HashMap<usize, BTreeSet<usize>>,
    k: u16,
) -> (BTreeMap<usize, Vec<RepairPath>>, TilfaStats) {
    let k = (k.max(1)) as usize;
    let groups = group_by_x(targets);
    let group_count = groups.len();
    let shards = lpt_binpack(groups, k);

    let per_shard: Vec<Vec<(usize, Vec<RepairPath>)>> = shards
        .par_iter()
        .map(|shard| {
            let mut out = Vec::new();
            for (x, ts) in shard {
                // One PC tree per group; dropped at group end so a
                // shard keeps at most one tree alive.
                let pc = spf_calc(
                    graph,
                    source,
                    &[*x],
                    &SpfOpt::full_path(),
                    &SpfDirect::Normal,
                );
                let p = &p_sets[x];
                for t in ts {
                    let q = q_space_vertices(graph, t.d, &[t.x]);
                    let repairs = pc
                        .get(&t.d)
                        .map(|dp| {
                            repair_from_parts(graph, source, p, &q, &dp.paths, &dp.first_hop_links)
                        })
                        .unwrap_or_default();
                    out.push((t.d, repairs));
                }
            }
            out
        })
        .collect();

    let stats = TilfaStats {
        q_spf: targets.len(),
        pc_spf: group_count,
        pc_deduped: targets.len() - group_count,
        // Groups are never split, so the effective parallelism is also
        // capped by the group count, not just K and the pool.
        width: k.min(group_count).min(rayon::current_num_threads()),
        ..TilfaStats::default()
    };
    (
        collect_nonempty(per_shard.into_iter().flatten().collect()),
        stats,
    )
}

/// Insert-if-nonempty, matching the historical per-destination loop:
/// a destination with no computable repair is absent from the map,
/// not present-with-empty.
fn collect_nonempty(pairs: Vec<(usize, Vec<RepairPath>)>) -> BTreeMap<usize, Vec<RepairPath>> {
    pairs
        .into_iter()
        .filter(|(_, repairs)| !repairs.is_empty())
        .collect()
}

/// Group targets by protected node, sorted by `x` for determinism.
fn group_by_x(targets: &[TilfaTarget]) -> Vec<XGroup> {
    let mut groups: BTreeMap<usize, Vec<TilfaTarget>> = BTreeMap::new();
    for t in targets {
        groups.entry(t.x).or_default().push(*t);
    }
    groups.into_iter().collect()
}

/// Longest-processing-time bin packing: groups sorted by target count
/// (descending, `x` ascending as the deterministic tie-break), each
/// placed into the currently least-loaded bin (lowest index on ties).
/// Returns at most `k` non-empty bins; a group is never split, which
/// is what keeps the per-shard PC-tree sharing exact.
fn lpt_binpack(mut groups: Vec<XGroup>, k: usize) -> Vec<Vec<XGroup>> {
    groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    let bins = k.min(groups.len()).max(1);
    let mut shards: Vec<Vec<XGroup>> = vec![Vec::new(); bins];
    let mut loads = vec![0usize; bins];
    for group in groups {
        let lightest = loads
            .iter()
            .enumerate()
            .min_by_key(|(idx, load)| (**load, *idx))
            .map(|(idx, _)| idx)
            .unwrap_or(0);
        loads[lightest] += group.1.len();
        shards[lightest].push(group);
    }
    shards.retain(|shard| !shard.is_empty());
    shards
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spf::calc::fixtures::*;
    use crate::spf::calc::{Link, Vertex, spf, tilfa};

    /// Deterministic splitmix-style generator — no rand dependency,
    /// stable across platforms so the random-graph cases are
    /// reproducible from the seed alone.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }
    }

    /// Strongly-connected random graph: a bidirectional ring backbone
    /// plus ~2n extra random edges. No parallel duplicate edges and
    /// `link_id` 0 everywhere, so repair-path equality is exact (the
    /// `first_hop_links` HashSet pick is degenerate at a single
    /// link_id value).
    fn random_graph(seed: u64, n: usize) -> Graph {
        let mut graph: Graph = BTreeMap::new();
        for i in 0..n {
            graph.insert(i, Vertex::new_node(&format!("N{i}"), i));
        }
        let mut rng = Lcg(seed);
        let mut edges = BTreeSet::new();
        for i in 0..n {
            edges.insert((i, (i + 1) % n));
            edges.insert(((i + 1) % n, i));
        }
        for _ in 0..2 * n {
            let a = (rng.next() as usize) % n;
            let b = (rng.next() as usize) % n;
            if a != b {
                edges.insert((a, b));
                edges.insert((b, a));
            }
        }
        for (a, b) in edges {
            let cost = 1 + (rng.next() % 10) as u32;
            graph
                .get_mut(&a)
                .unwrap()
                .olinks
                .push(Link::new(a, b, cost));
            graph
                .get_mut(&b)
                .unwrap()
                .ilinks
                .push(Link::new(a, b, cost));
        }
        graph
    }

    /// IS-IS-style target derivation (mirrors
    /// `isis::tilfa::tilfa_targets` minus the lsp_map pseudonode-
    /// destination skip, which doesn't affect mode equivalence).
    fn derive_targets(
        graph: &Graph,
        source: usize,
        primary: &BTreeMap<usize, Path>,
    ) -> Vec<TilfaTarget> {
        let mut targets = Vec::new();
        for (d, path) in primary {
            if *d == source || path.paths.len() > 1 {
                continue;
            }
            let Some(first) = path.paths.first() else {
                continue;
            };
            if first.is_empty() {
                continue;
            }
            let x = if graph.get(&first[0]).is_some_and(|v| v.is_pseudo_node()) {
                first.get(1).copied().unwrap_or(first[0])
            } else {
                first[0]
            };
            targets.push(TilfaTarget { d: *d, x });
        }
        targets
    }

    /// The reference: the historical per-destination `spf::tilfa`
    /// loop (3 SPFs per destination, insert-if-nonempty).
    fn reference(
        graph: &Graph,
        source: usize,
        targets: &[TilfaTarget],
    ) -> BTreeMap<usize, Vec<RepairPath>> {
        let mut out = BTreeMap::new();
        for t in targets {
            let repairs = tilfa(graph, source, t.d, &[t.x]);
            if !repairs.is_empty() {
                out.insert(t.d, repairs);
            }
        }
        out
    }

    #[test]
    fn modes_match_reference() {
        let mut cases: Vec<Graph> = vec![tilfa_graph(), isis_lan_graph(), mixed_lan_p2p_graph()];
        for seed in 1..=5u64 {
            cases.push(random_graph(seed, 20 + (seed as usize) * 4));
        }

        let modes = [
            TilfaComputeMode::Serial,
            TilfaComputeMode::Conservative,
            TilfaComputeMode::Aggressive,
            TilfaComputeMode::Sharding(1),
            TilfaComputeMode::Sharding(2),
            TilfaComputeMode::Sharding(7),
        ];

        for (idx, graph) in cases.iter().enumerate() {
            let source = 0;
            let primary = spf(graph, source, &SpfOpt::full_path());
            let targets = derive_targets(graph, source, &primary);
            assert!(!targets.is_empty(), "case {idx}: no targets derived");
            let want = reference(graph, source, &targets);
            for mode in modes {
                let (got, stats) = tilfa_compute(graph, source, &primary, &targets, mode);
                assert_eq!(got, want, "case {idx} mode {mode:?}");
                assert_eq!(stats.targets, targets.len(), "case {idx} mode {mode:?}");
            }
        }
    }

    /// SPF counters per mode on the RFC 9855 fixture: 6 targets over
    /// 3 distinct protected nodes (d=4 is ECMP-skipped). Serial and
    /// conservative recompute PC per target; aggressive and sharding
    /// share it per x.
    #[test]
    fn stats_reflect_spf_sharing() {
        let graph = tilfa_graph();
        let primary = spf(&graph, 0, &SpfOpt::full_path());
        let targets = derive_targets(&graph, 0, &primary);
        assert_eq!(targets.len(), 6);
        let distinct_x: BTreeSet<usize> = targets.iter().map(|t| t.x).collect();
        assert_eq!(distinct_x.len(), 3);

        let (_, serial) = tilfa_compute(&graph, 0, &primary, &targets, TilfaComputeMode::Serial);
        assert_eq!((serial.q_spf, serial.pc_spf, serial.pc_deduped), (6, 6, 0));
        assert_eq!(serial.width, 1);

        let (_, aggr) = tilfa_compute(&graph, 0, &primary, &targets, TilfaComputeMode::Aggressive);
        assert_eq!((aggr.q_spf, aggr.pc_spf, aggr.pc_deduped), (6, 3, 3));

        let (_, shard) =
            tilfa_compute(&graph, 0, &primary, &targets, TilfaComputeMode::Sharding(2));
        assert_eq!((shard.q_spf, shard.pc_spf, shard.pc_deduped), (6, 3, 3));
        assert!(shard.width <= 2);
    }

    #[test]
    fn empty_targets_short_circuit() {
        let graph = tilfa_graph();
        let primary = spf(&graph, 0, &SpfOpt::full_path());
        for mode in [
            TilfaComputeMode::Serial,
            TilfaComputeMode::Conservative,
            TilfaComputeMode::Aggressive,
            TilfaComputeMode::Sharding(4),
        ] {
            let (got, stats) = tilfa_compute(&graph, 0, &primary, &[], mode);
            assert!(got.is_empty());
            assert_eq!(stats.targets, 0);
        }
    }

    /// Manual perf harness — not a correctness gate (CI never runs
    /// ignored tests). Compares the legacy 3-SPF reference loop and
    /// every compute mode on a ~400-vertex random graph:
    ///
    ///   cargo test --release -p zebra-rs tilfa_perf -- --ignored --nocapture
    ///
    /// Debug builds are ~10× slower and skew the comparison; use
    /// `--release`. The mode outputs are also cross-checked for
    /// equality so a perf run doubles as a large-graph equivalence
    /// run.
    #[test]
    #[ignore = "manual perf harness; run with --release --ignored --nocapture"]
    fn tilfa_perf_modes() {
        let n = 400;
        let graph = random_graph(42, n);
        let primary = spf(&graph, 0, &SpfOpt::full_path());
        let targets = derive_targets(&graph, 0, &primary);
        let distinct_x: BTreeSet<usize> = targets.iter().map(|t| t.x).collect();
        println!(
            "graph: {n} vertices, {} targets, {} protected first-hops",
            targets.len(),
            distinct_x.len()
        );

        let t0 = Instant::now();
        let want = reference(&graph, 0, &targets);
        println!(
            "{:<20} {:>12?}  (3 SPFs per target)",
            "reference",
            t0.elapsed()
        );

        for mode in [
            TilfaComputeMode::Serial,
            TilfaComputeMode::Conservative,
            TilfaComputeMode::Aggressive,
            TilfaComputeMode::Sharding(2),
            TilfaComputeMode::Sharding(8),
        ] {
            let t0 = Instant::now();
            let (got, stats) = tilfa_compute(&graph, 0, &primary, &targets, mode);
            println!(
                "{:<20} {:>12?}  spf{{q={} pc={}}} width={}",
                mode.to_string(),
                t0.elapsed(),
                stats.q_spf,
                stats.pc_spf,
                stats.width
            );
            assert_eq!(got, want, "mode {mode:?} diverged from reference");
        }
    }

    fn group(x: usize, n: usize) -> XGroup {
        (
            x,
            (0..n).map(|i| TilfaTarget { d: 100 * x + i, x }).collect(),
        )
    }

    #[test]
    fn lpt_binpack_balances_without_splitting_groups() {
        // Sizes 5,4,3,2,1 into 2 bins → LPT loads 8/7.
        let groups = vec![
            group(1, 5),
            group(2, 4),
            group(3, 3),
            group(4, 2),
            group(5, 1),
        ];
        let shards = lpt_binpack(groups, 2);
        assert_eq!(shards.len(), 2);
        let mut loads: Vec<usize> = shards
            .iter()
            .map(|s| s.iter().map(|(_, ts)| ts.len()).sum())
            .collect();
        loads.sort();
        assert_eq!(loads, vec![7, 8]);
        // Every group lands in exactly one shard (no split, no loss).
        let mut xs: Vec<usize> = shards
            .iter()
            .flat_map(|s| s.iter().map(|(x, _)| *x))
            .collect();
        xs.sort();
        assert_eq!(xs, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn lpt_binpack_bounds() {
        // k = 1 → everything in one shard.
        let shards = lpt_binpack(vec![group(1, 3), group(2, 2)], 1);
        assert_eq!(shards.len(), 1);
        // k > group count → one group per shard, no empties.
        let shards = lpt_binpack(vec![group(1, 3), group(2, 2)], 8);
        assert_eq!(shards.len(), 2);
        assert!(shards.iter().all(|s| s.len() == 1));
    }

    #[test]
    fn group_by_x_is_sorted_and_lossless() {
        let targets = vec![
            TilfaTarget { d: 9, x: 3 },
            TilfaTarget { d: 5, x: 1 },
            TilfaTarget { d: 6, x: 3 },
            TilfaTarget { d: 7, x: 1 },
        ];
        let groups = group_by_x(&targets);
        let xs: Vec<usize> = groups.iter().map(|(x, _)| *x).collect();
        assert_eq!(xs, vec![1, 3]);
        let total: usize = groups.iter().map(|(_, ts)| ts.len()).sum();
        assert_eq!(total, targets.len());
    }
}
