//! Commit-time checks on MPLS labels (docs/design/mpls-label-allocation.md
//! §7): everything about a label that can be checked is checked before the
//! commit is dispatched, so the label table never holds a collision for an
//! operator to clear later.
//!
//! - A static `mpls label` binding: 16 up to the kernel's last usable
//!   label, and outside every segment-routing block's SRGB and SRLB, the
//!   dynamic range, and every label block handed out (one handed out before
//!   the dynamic range moved can lie outside it). The dynamic allocators
//!   take labels only from those, so a static binding kept out of them
//!   never collides.
//! - The dynamic range (`mpls label-range dynamic`): not empty. Its bounds
//!   are kept inside the label space by the schema. Label blocks already
//!   handed out outside a new range do not block it: they stay until
//!   released.
//! - A configured absolute Adjacency-SID: inside the SRLB the IGPs use (the
//!   `default` block's), and configured on one interface only. One a
//!   dynamic Adjacency-SID holds is fine: its holder is moved (phase 3b).
//! - A `segment-routing block`: inside the label space, its SRGB and SRLB
//!   apart from each other and from every other block, not over a label
//!   block BGP holds (the refusal names the nearest free range of that
//!   size), and, for the `default` block, wide enough for every configured
//!   Prefix-SID index. A static binding it would cover is
//!   reported from the binding's side, as is an Adjacency-SID left outside
//!   its SRLB.
//!
//! The checks look at the whole candidate, but a commit is rejected only
//! for a violation the running config does not already have
//! ([`new_violations`]). A violation an earlier release let in, or the
//! startup load warned about, then does not block every later commit, while
//! a change that creates one (a block moved over an untouched static
//! binding, say) is still refused.

use std::collections::{BTreeMap, BTreeSet};

use crate::rib::Block;
use crate::rib::label_space::{DYNAMIC_START, PLATFORM_LABELS};
use crate::rib::segment_routing::block::{BlockConfig, DEFAULT_BLOCK_NAME};
use crate::spf::label_block::LabelBlock;

/// The lowest label a static binding may use: 0..=15 are reserved
/// (RFC 3032 §2.1, RFC 7274).
const FIRST_STATIC: u32 = 16;

/// A config leaf: its callback path (keys removed) and its arguments,
/// the list keys on the way down and then the value.
pub type Leaf = (String, Vec<String>);

/// What the label checks read from one config.
#[derive(Debug, Default)]
struct Labels {
    blocks: BTreeMap<String, BlockConfig>,
    statics: BTreeSet<u32>,
    /// Configured absolute Adjacency-SIDs: who, and the label.
    adj_sids: Vec<(String, u32)>,
    /// Configured Prefix-SID indexes: who, and the index.
    prefix_sids: Vec<(String, u32)>,
    /// `mpls label-range dynamic` start and end, when configured.
    dynamic: (Option<u32>, Option<u32>),
}

impl Labels {
    fn from_leaves(leaves: &[Leaf]) -> Self {
        let mut labels = Labels::default();
        for (path, args) in leaves {
            let arg = |i: usize| args.get(i).map(String::as_str).unwrap_or("");
            let num = |i: usize| arg(i).parse::<u32>().ok();
            let value = || args.last().and_then(|v| v.parse::<u32>().ok());
            if let Some(leaf) = path.strip_prefix("/mpls/label-range/dynamic/") {
                match leaf {
                    "start" => labels.dynamic.0 = value(),
                    "end" => labels.dynamic.1 = value(),
                    _ => {}
                }
            } else if let Some(leaf) = path.strip_prefix("/segment-routing/block") {
                let block = labels.blocks.entry(arg(0).to_string()).or_default();
                match leaf {
                    "/global/start" => block.global_start = value(),
                    "/global/range" => block.global_range = value(),
                    "/local/start" => block.local_start = value(),
                    "/local/range" => block.local_range = value(),
                    _ => {}
                }
            } else if path.starts_with("/router/static/mpls/label") {
                labels.statics.extend(num(0));
            } else if path.starts_with("/router/static/vrf/mpls/label") {
                labels.statics.extend(num(1));
            } else if let Some((proto, leaf)) = path
                .strip_prefix("/router/ospf/")
                .map(|leaf| ("OSPF", leaf))
                .or_else(|| path.strip_prefix("/router/ospfv3/").map(|l| ("OSPFv3", l)))
            {
                let who = format!("{proto} area {} interface {}", arg(0), arg(1));
                match leaf {
                    "area/interface/adjacency-sid/absolute" => {
                        labels.adj_sids.extend(value().map(|l| (who, l)));
                    }
                    "area/interface/prefix-sid/index" => {
                        labels
                            .prefix_sids
                            .extend(value().map(|i| (format!("{who} prefix-sid"), i)));
                    }
                    "area/interface/flex-algo-prefix-sid/index" => {
                        labels.prefix_sids.extend(
                            value().map(|i| (format!("{who} flex-algo {} prefix-sid", arg(2)), i)),
                        );
                    }
                    _ => {}
                }
            } else if let Some(leaf) = path.strip_prefix("/router/isis/") {
                match leaf {
                    "interface/ipv4/prefix-sid/index" => labels.prefix_sids.extend(
                        value().map(|i| (format!("IS-IS interface {} prefix-sid", arg(0)), i)),
                    ),
                    "interface/ipv4/flex-algo-prefix-sid/index" => {
                        labels.prefix_sids.extend(value().map(|i| {
                            (
                                format!(
                                    "IS-IS interface {} flex-algo {} prefix-sid",
                                    arg(0),
                                    arg(1)
                                ),
                                i,
                            )
                        }))
                    }
                    "area-proxy/area-sid/index" => labels
                        .prefix_sids
                        .extend(value().map(|i| ("IS-IS area-proxy area-sid".to_string(), i))),
                    _ => {}
                }
            }
        }
        labels
    }

    /// Every block as the RIB applies it: the `default` block is there with
    /// its canonical ranges until it is configured, and a configured range
    /// needs both its start and its range.
    fn effective_blocks(&self) -> BTreeMap<String, Block> {
        let mut blocks: BTreeMap<String, Block> = self
            .blocks
            .iter()
            .map(|(name, config)| (name.clone(), config.to_block()))
            .collect();
        blocks
            .entry(DEFAULT_BLOCK_NAME.to_string())
            .or_insert_with(Block::default_block);
        blocks
    }
}

/// `[first, last]` of a non-empty block.
fn span(block: &LabelBlock) -> Option<(u32, u32)> {
    (block.start < block.end).then(|| (block.start, block.end - 1))
}

fn overlap(a: (u32, u32), b: (u32, u32)) -> bool {
    a.0 <= b.1 && b.0 <= a.1
}

/// `[first, last]` of the free range of `size` labels nearest `start`,
/// clear of every range in `taken`. The starts that fit form intervals, so
/// the nearest one is `start` itself or an end of one of them: just past a
/// taken range, just before one, or at either end of the label space.
fn nearest_free(start: u32, size: u32, taken: &[(u32, u32)]) -> Option<(u32, u32)> {
    let fits = |first: u32| {
        let last = first.checked_add(size.checked_sub(1)?)?;
        (first >= FIRST_STATIC
            && last < PLATFORM_LABELS
            && !taken.iter().any(|t| overlap((first, last), *t)))
        .then_some((first, last))
    };
    let mut starts = vec![start, FIRST_STATIC];
    starts.extend(PLATFORM_LABELS.checked_sub(size));
    for (first, last) in taken {
        starts.push(last + 1);
        starts.extend(first.checked_sub(size));
    }
    starts
        .into_iter()
        .filter_map(fits)
        .min_by_key(|(first, _)| (first.abs_diff(start), *first))
}

/// Every label violation in a config whose leaves are `leaves`, given the
/// label blocks handed out at run time (`held`, with their owners). Each is
/// a message naming the offending config, the same text for the same
/// violation, so two configs' sets can be compared.
pub fn violations(leaves: &[Leaf], held: &[(LabelBlock, String)]) -> BTreeSet<String> {
    let labels = Labels::from_leaves(leaves);
    let blocks = labels.effective_blocks();
    let mut out = BTreeSet::new();

    // Every SRGB and SRLB, named.
    let regions: Vec<(String, (u32, u32))> = blocks
        .iter()
        .flat_map(|(name, block)| {
            [("SRGB", &block.global), ("SRLB", &block.local)]
                .into_iter()
                .filter_map(move |(kind, range)| {
                    let range = range.as_ref().and_then(span)?;
                    Some((format!("the {kind} of segment-routing block {name}"), range))
                })
        })
        .collect();
    let last_label = PLATFORM_LABELS - 1;
    let held_spans: Vec<(u32, u32)> = held.iter().filter_map(|(b, _)| span(b)).collect();

    // The dynamic range, as the RIB applies it: each bound defaults on its
    // own.
    let dynamic = (
        labels.dynamic.0.unwrap_or(DYNAMIC_START),
        labels.dynamic.1.unwrap_or(last_label),
    );
    if dynamic.0 > dynamic.1 {
        out.insert(format!(
            "mpls label-range dynamic {}-{} is empty: its start is above its end",
            dynamic.0, dynamic.1
        ));
    }

    for label in &labels.statics {
        if *label < FIRST_STATIC || *label > last_label {
            out.insert(format!(
                "static MPLS label {label} is outside {FIRST_STATIC}-{last_label}"
            ));
            continue;
        }
        for (region, (first, last)) in &regions {
            if (*first..=*last).contains(label) {
                out.insert(format!(
                    "static MPLS label {label} is in {region} ({first}-{last})"
                ));
            }
        }
        if (dynamic.0..=dynamic.1).contains(label) {
            out.insert(format!(
                "static MPLS label {label} is in the dynamic label range ({}-{})",
                dynamic.0, dynamic.1
            ));
        }
        // A block handed out before the dynamic range moved stays where it
        // is, possibly outside the range now.
        for (block, proto) in held {
            if let Some((first, last)) = span(block)
                && (first..=last).contains(label)
            {
                out.insert(format!(
                    "static MPLS label {label} is in a label block {proto} holds ({first}-{last})"
                ));
            }
        }
    }

    let default = &blocks[DEFAULT_BLOCK_NAME];
    let srlb = default.local.as_ref().and_then(span);
    let mut by_label: BTreeMap<u32, Vec<&str>> = BTreeMap::new();
    for (who, label) in &labels.adj_sids {
        by_label.entry(*label).or_default().push(who);
        match srlb {
            Some((first, last)) if !(first..=last).contains(label) => {
                out.insert(format!(
                    "{who} adjacency-sid absolute {label} is outside the SRLB ({first}-{last})"
                ));
            }
            None => {
                out.insert(format!(
                    "{who} adjacency-sid absolute {label} needs an SRLB, and segment-routing block {DEFAULT_BLOCK_NAME} has none"
                ));
            }
            _ => {}
        }
    }
    for (label, whos) in by_label {
        if whos.len() > 1 {
            out.insert(format!(
                "adjacency-sid absolute {label} is configured more than once: {}",
                whos.join(", ")
            ));
        }
    }

    for (name, block) in &blocks {
        for (kind, range) in [("global", &block.global), ("local", &block.local)] {
            let Some(range) = range.as_ref() else {
                continue;
            };
            if range.start < range.end
                && (range.start < FIRST_STATIC || range.end > PLATFORM_LABELS)
            {
                out.insert(format!(
                    "segment-routing block {name} {kind} ({}-{}) is outside the label space ({FIRST_STATIC}-{last_label})",
                    range.start,
                    range.end - 1
                ));
            }
        }
        if let (Some(g), Some(l)) = (
            block.global.as_ref().and_then(span),
            block.local.as_ref().and_then(span),
        ) && overlap(g, l)
        {
            out.insert(format!(
                "segment-routing block {name}: its SRGB and SRLB overlap"
            ));
        }
        for (held, proto) in held {
            let Some(chunk) = span(held) else {
                continue;
            };
            for (kind, range) in [("SRGB", &block.global), ("SRLB", &block.local)] {
                let Some(range) = range.as_ref().and_then(span) else {
                    continue;
                };
                if !overlap(range, chunk) {
                    continue;
                }
                // Somewhere it would fit: clear of what BGP holds, the
                // other SR ranges and the static bindings.
                let region = format!("the {kind} of segment-routing block {name}");
                let taken: Vec<(u32, u32)> = held_spans
                    .iter()
                    .copied()
                    .chain(
                        regions
                            .iter()
                            .filter(|(other, _)| *other != region)
                            .map(|(_, r)| *r),
                    )
                    .chain(labels.statics.iter().map(|l| (*l, *l)))
                    .collect();
                let size = range.1 - range.0 + 1;
                let instead = match nearest_free(range.0, size, &taken) {
                    Some((first, last)) => {
                        format!("the nearest free range of {size} labels is {first}-{last}")
                    }
                    None => format!("no range of {size} labels is free"),
                };
                out.insert(format!(
                    "{region} ({}-{}) covers labels {proto} holds ({}-{}); {instead}",
                    range.0, range.1, chunk.0, chunk.1
                ));
            }
        }
    }
    // Two blocks over one another.
    let names: Vec<&String> = blocks.keys().collect();
    for (i, a) in names.iter().enumerate() {
        for b in &names[i + 1..] {
            let ranges = |block: &Block| -> Vec<(u32, u32)> {
                [&block.global, &block.local]
                    .into_iter()
                    .filter_map(|r| r.as_ref().and_then(span))
                    .collect()
            };
            let clash = ranges(&blocks[*a])
                .iter()
                .any(|x| ranges(&blocks[*b]).iter().any(|y| overlap(*x, *y)));
            if clash {
                out.insert(format!("segment-routing blocks {a} and {b} overlap"));
            }
        }
    }

    // The IGPs' Prefix-SID indexes resolve against the default SRGB.
    if let Some(srgb) = default.global.as_ref()
        && srgb.start < srgb.end
    {
        let size = srgb.end - srgb.start;
        for (who, index) in &labels.prefix_sids {
            if *index >= size {
                out.insert(format!(
                    "{who} index {index} does not fit the SRGB ({}-{}, {size} labels)",
                    srgb.start,
                    srgb.end - 1
                ));
            }
        }
    }
    out
}

/// The violations `candidate` has that `running` does not: those this
/// commit would introduce.
pub fn new_violations(
    candidate: &[Leaf],
    running: &[Leaf],
    held: &[(LabelBlock, String)],
) -> Vec<String> {
    let before = violations(running, held);
    violations(candidate, held)
        .into_iter()
        .filter(|v| !before.contains(v))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(path: &str, args: &[&str]) -> Leaf {
        (
            path.to_string(),
            args.iter().map(|arg| arg.to_string()).collect(),
        )
    }

    /// A `segment-routing block` with both ranges.
    fn block(name: &str, srgb: (u32, u32), srlb: (u32, u32)) -> Vec<Leaf> {
        let (gs, gr, ls, lr) = (
            srgb.0.to_string(),
            srgb.1.to_string(),
            srlb.0.to_string(),
            srlb.1.to_string(),
        );
        vec![
            leaf("/segment-routing/block/global/start", &[name, &gs]),
            leaf("/segment-routing/block/global/range", &[name, &gr]),
            leaf("/segment-routing/block/local/start", &[name, &ls]),
            leaf("/segment-routing/block/local/range", &[name, &lr]),
        ]
    }

    fn static_label(label: u32) -> Leaf {
        leaf("/router/static/mpls/label", &[&label.to_string()])
    }

    fn adj_sid(proto: &str, ifname: &str, label: u32) -> Leaf {
        leaf(
            &format!("/router/{proto}/area/interface/adjacency-sid/absolute"),
            &["0.0.0.0", ifname, &label.to_string()],
        )
    }

    fn check(leaves: &[Leaf]) -> Vec<String> {
        violations(leaves, &[]).into_iter().collect()
    }

    #[test]
    fn the_defaults_are_clean() {
        assert!(check(&[]).is_empty());
    }

    /// Static bindings live below the SR blocks: 16-14999 by default.
    #[test]
    fn a_static_label_stays_out_of_the_sr_blocks_and_the_dynamic_range() {
        assert!(check(&[static_label(16), static_label(14999)]).is_empty());
        assert_eq!(
            check(&[static_label(15000)]),
            vec![
                "static MPLS label 15000 is in the SRLB of segment-routing block default (15000-15999)"
            ]
        );
        assert_eq!(
            check(&[static_label(16000)]),
            vec![
                "static MPLS label 16000 is in the SRGB of segment-routing block default (16000-23999)"
            ]
        );
        assert_eq!(
            check(&[static_label(15999), static_label(23999)]),
            vec![
                "static MPLS label 15999 is in the SRLB of segment-routing block default (15000-15999)",
                "static MPLS label 23999 is in the SRGB of segment-routing block default (16000-23999)",
            ]
        );
        assert_eq!(
            check(&[static_label(24000)]),
            vec!["static MPLS label 24000 is in the dynamic label range (24000-1048574)"]
        );
        assert_eq!(
            check(&[static_label(15)]),
            vec!["static MPLS label 15 is outside 16-1048574"]
        );
        assert_eq!(
            check(&[static_label(1048575)]),
            vec!["static MPLS label 1048575 is outside 16-1048574"]
        );
        // The kernel's last usable label is a label, just a dynamic one.
        assert_eq!(
            check(&[static_label(1048574)]),
            vec!["static MPLS label 1048574 is in the dynamic label range (24000-1048574)"]
        );
        // A VRF's static bindings share the one label table.
        assert_eq!(
            check(&[leaf("/router/static/vrf/mpls/label", &["blue", "15000"])]).len(),
            1
        );
    }

    fn dynamic(start: Option<u32>, end: Option<u32>) -> Vec<Leaf> {
        let mut leaves = Vec::new();
        if let Some(start) = start {
            leaves.push(leaf(
                "/mpls/label-range/dynamic/start",
                &[&start.to_string()],
            ));
        }
        if let Some(end) = end {
            leaves.push(leaf("/mpls/label-range/dynamic/end", &[&end.to_string()]));
        }
        leaves
    }

    /// A configured dynamic range moves where static bindings may go: each
    /// bound defaults on its own, and the labels above a range ended early
    /// are static too.
    #[test]
    fn a_static_label_stays_out_of_the_configured_dynamic_range() {
        let mut leaves = dynamic(Some(30000), None);
        leaves.extend([static_label(24000), static_label(29999)]);
        assert!(check(&leaves).is_empty());
        leaves.push(static_label(30000));
        assert_eq!(
            check(&leaves),
            vec!["static MPLS label 30000 is in the dynamic label range (30000-1048574)"]
        );

        let mut leaves = dynamic(None, Some(99999));
        leaves.extend([static_label(100000), static_label(1048574)]);
        assert!(check(&leaves).is_empty());
        leaves.push(static_label(99999));
        assert_eq!(
            check(&leaves),
            vec!["static MPLS label 99999 is in the dynamic label range (24000-99999)"]
        );
    }

    #[test]
    fn a_dynamic_range_is_not_empty() {
        assert!(check(&dynamic(Some(30000), Some(30000))).is_empty());
        assert_eq!(
            check(&dynamic(Some(40000), Some(30000))),
            vec!["mpls label-range dynamic 40000-30000 is empty: its start is above its end"]
        );
        // An end below the default start, with no start configured.
        assert_eq!(
            check(&dynamic(None, Some(20000))),
            vec!["mpls label-range dynamic 24000-20000 is empty: its start is above its end"]
        );
    }

    /// Growing the range over a static binding breaks it; shrinking it
    /// away from one does not, nor does moving it while label blocks are
    /// held: those stay until released.
    #[test]
    fn a_dynamic_range_change_is_refused_only_over_a_static_binding() {
        let running = [static_label(100)];
        assert!(check(&running).is_empty());
        let held = [(
            LabelBlock {
                start: 24000,
                end: 25024,
            },
            "bgp".to_string(),
        )];
        let mut moved = running.to_vec();
        moved.extend(dynamic(Some(30000), Some(99999)));
        assert!(new_violations(&moved, &running, &held).is_empty());

        // BGP's block stays below the moved range: a static binding there
        // would share its labels.
        moved.push(static_label(24500));
        assert_eq!(
            new_violations(&moved, &running, &held),
            vec!["static MPLS label 24500 is in a label block bgp holds (24000-25023)"]
        );

        let mut grown = running.to_vec();
        grown.extend(dynamic(Some(16), None));
        assert_eq!(
            new_violations(&grown, &running, &held),
            vec!["static MPLS label 100 is in the dynamic label range (16-1048574)"]
        );
    }

    #[test]
    fn an_absolute_adj_sid_lies_in_the_srlb_on_one_interface() {
        assert!(check(&[adj_sid("ospf", "eth1", 15000)]).is_empty());
        assert!(check(&[adj_sid("ospf", "eth1", 15999)]).is_empty());
        assert_eq!(
            check(&[adj_sid("ospf", "eth1", 14999)]),
            vec![
                "OSPF area 0.0.0.0 interface eth1 adjacency-sid absolute 14999 is outside the SRLB (15000-15999)"
            ]
        );
        assert_eq!(
            check(&[adj_sid("ospf", "eth1", 16000)]),
            vec![
                "OSPF area 0.0.0.0 interface eth1 adjacency-sid absolute 16000 is outside the SRLB (15000-15999)"
            ]
        );
        // A configured default block without a local range has no SRLB.
        assert_eq!(
            check(&[
                leaf("/segment-routing/block/global/start", &["default", "16000"]),
                leaf("/segment-routing/block/global/range", &["default", "8000"]),
                adj_sid("ospf", "eth1", 15000),
            ]),
            vec![
                "OSPF area 0.0.0.0 interface eth1 adjacency-sid absolute 15000 needs an SRLB, and segment-routing block default has none"
            ]
        );
        assert_eq!(
            check(&[
                adj_sid("ospf", "eth1", 15000),
                adj_sid("ospfv3", "eth2", 15000)
            ]),
            vec![
                "adjacency-sid absolute 15000 is configured more than once: OSPF area 0.0.0.0 interface eth1, OSPFv3 area 0.0.0.0 interface eth2"
            ]
        );
    }

    #[test]
    fn a_block_stays_inside_the_label_space_and_apart() {
        // Up to the kernel's last usable label, and from 16.
        assert!(check(&block("default", (1040575, 8000), (16, 1000))).is_empty());
        assert_eq!(
            check(&block("default", (1040576, 8000), (15, 1000))),
            vec![
                "segment-routing block default global (1040576-1048575) is outside the label space (16-1048574)",
                "segment-routing block default local (15-1014) is outside the label space (16-1048574)",
            ]
        );
        assert_eq!(
            check(&block("default", (10, 100), (15000, 1000))),
            vec![
                "segment-routing block default global (10-109) is outside the label space (16-1048574)"
            ]
        );
        assert_eq!(
            check(&block("default", (16000, 8000), (16500, 100))),
            vec!["segment-routing block default: its SRGB and SRLB overlap"]
        );
        // One label in common is an overlap; adjacent is not.
        assert_eq!(
            check(&block("default", (16000, 8000), (15000, 1001))),
            vec!["segment-routing block default: its SRGB and SRLB overlap"]
        );
        let mut two = block("default", (16000, 8000), (15000, 1000));
        two.extend(block("core", (20000, 100), (30000, 100)));
        assert_eq!(
            check(&two),
            vec!["segment-routing blocks core and default overlap"]
        );
    }

    /// A block over labels BGP holds would put both at the same labels.
    #[test]
    fn a_block_does_not_cover_a_bgp_label_block() {
        let held = [(
            LabelBlock {
                start: 24000,
                end: 25024,
            },
            "bgp".to_string(),
        )];
        let leaves = block("default", (24500, 8000), (15000, 1000));
        assert_eq!(
            violations(&leaves, &held).into_iter().collect::<Vec<_>>(),
            vec![
                "the SRGB of segment-routing block default (24500-32499) covers labels bgp holds (24000-25023); the nearest free range of 8000 labels is 25024-33023"
            ]
        );
    }

    /// The nearest free range keeps clear of everything taken, on either
    /// side of the requested start, inside the label space.
    #[test]
    fn the_nearest_free_range_avoids_what_is_taken() {
        // Free where asked.
        assert_eq!(nearest_free(100, 10, &[]), Some((100, 109)));
        // Past the obstacle is nearer than before it.
        assert_eq!(nearest_free(100, 10, &[(95, 104)]), Some((105, 114)));
        // Before it is nearer than past it.
        assert_eq!(nearest_free(100, 10, &[(100, 120)]), Some((90, 99)));
        // A gap too small is skipped.
        assert_eq!(
            nearest_free(100, 10, &[(85, 99), (105, 120)]),
            Some((121, 130))
        );
        // Not below 16 or past the last label.
        assert_eq!(nearest_free(10, 10, &[]), Some((16, 25)));
        assert_eq!(nearest_free(1048570, 10, &[]), Some((1048565, 1048574)));
        assert_eq!(nearest_free(1048566, 10, &[]), Some((1048565, 1048574)));
        // A static binding counts as taken.
        let mut leaves = block("default", (24500, 8000), (15000, 1000));
        leaves.push(static_label(25100));
        let held = [(
            LabelBlock {
                start: 24000,
                end: 25024,
            },
            "bgp".to_string(),
        )];
        assert!(
            violations(&leaves, &held)
                .iter()
                .any(|v| v.ends_with("the nearest free range of 8000 labels is 25101-33100")),
            "{:?}",
            violations(&leaves, &held)
        );
        assert_eq!(nearest_free(16, PLATFORM_LABELS, &[]), None);
    }

    /// Every IGP's Prefix-SID index, and IS-IS's Area SID, resolves against
    /// the default SRGB.
    #[test]
    fn a_prefix_sid_index_fits_the_srgb() {
        let mut leaves = block("default", (16000, 100), (15000, 1000));
        leaves.extend([
            leaf(
                "/router/isis/interface/ipv4/prefix-sid/index",
                &["lo", "99"],
            ),
            leaf(
                "/router/isis/interface/ipv4/prefix-sid/index",
                &["lo2", "100"],
            ),
            leaf(
                "/router/isis/interface/ipv4/flex-algo-prefix-sid/index",
                &["lo", "128", "150"],
            ),
            leaf(
                "/router/ospf/area/interface/prefix-sid/index",
                &["0.0.0.0", "lo", "200"],
            ),
            leaf("/router/isis/area-proxy/area-sid/index", &["300"]),
        ]);
        assert_eq!(
            check(&leaves),
            vec![
                "IS-IS area-proxy area-sid index 300 does not fit the SRGB (16000-16099, 100 labels)",
                "IS-IS interface lo flex-algo 128 prefix-sid index 150 does not fit the SRGB (16000-16099, 100 labels)",
                "IS-IS interface lo2 prefix-sid index 100 does not fit the SRGB (16000-16099, 100 labels)",
                "OSPF area 0.0.0.0 interface lo prefix-sid index 200 does not fit the SRGB (16000-16099, 100 labels)",
            ]
        );
    }

    /// A commit is refused only for what it breaks: a violation already
    /// running does not block it, a new one does, even when it comes from
    /// a change elsewhere (a block moved over an untouched binding).
    #[test]
    fn only_a_new_violation_refuses_a_commit() {
        let running = [static_label(30000)];
        let mut unrelated = running.to_vec();
        unrelated.push(static_label(100));
        assert!(new_violations(&unrelated, &running, &[]).is_empty());

        let mut another = running.to_vec();
        another.push(static_label(30001));
        assert_eq!(new_violations(&another, &running, &[]).len(), 1);

        let running = [static_label(100)];
        let mut moved = running.to_vec();
        moved.extend(block("default", (16000, 8000), (64, 100)));
        assert_eq!(
            new_violations(&moved, &running, &[]),
            vec!["static MPLS label 100 is in the SRLB of segment-routing block default (64-163)"]
        );
    }
}
