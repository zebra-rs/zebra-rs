//! `show mpls label range` and `show mpls label table [label <n>]`
//! (docs/design/mpls-label-allocation.md §8): the regions of the label space,
//! and what the RIB's [`LabelSpace`](super::label_space::LabelSpace) has
//! handed out in them, with owners and states.
//!
//! Only allocations are listed. Static bindings and Prefix-SID labels are
//! configuration, not allocations, and `show mpls ilm` shows them; the
//! regions say where each kind of label lives.

use std::fmt::Write;

use serde::Serialize;

use crate::config::Args;
use crate::spf::label_block::LabelBlock;

use super::Rib;
use super::label_space::{EntryKind, EntryState, Holder, LabelEntry, PLATFORM_LABELS};
use super::segment_routing::Block;

/// The last reserved label: 0..=15 (RFC 3032 §2.1, RFC 7274).
const RESERVED_LAST: u32 = 15;

/// What a region of the label space is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RegionKind {
    Reserved,
    Static,
    Srgb,
    Srlb,
    /// An SRGB no longer configured, still reserved while Prefix-SID
    /// labels move out of it (phase 4b).
    RetiredSrgb,
    Dynamic,
}

/// A region of the label space, `[first, last]`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Region {
    first: u32,
    last: u32,
    kind: RegionKind,
    /// The `segment-routing block` an SRGB or SRLB belongs to.
    block: Option<String>,
}

impl Region {
    fn new(first: u32, last: u32, kind: RegionKind) -> Self {
        Self {
            first,
            last,
            kind,
            block: None,
        }
    }

    fn name(&self) -> String {
        let block = self.block.as_deref().unwrap_or("-");
        match self.kind {
            RegionKind::Reserved => "reserved (RFC 3032, RFC 7274)".to_string(),
            RegionKind::Static => "static".to_string(),
            RegionKind::Srgb => format!("SRGB of segment-routing block {block}"),
            RegionKind::Srlb => format!("SRLB of segment-routing block {block}"),
            RegionKind::RetiredSrgb => "retired SRGB, held while Prefix-SIDs move".to_string(),
            RegionKind::Dynamic => "dynamic".to_string(),
        }
    }

    fn contains(&self, label: u32) -> bool {
        (self.first..=self.last).contains(&label)
    }
}

/// Every region, by first label: the reserved labels, each block's SRGB
/// and SRLB, each retired SRGB, the dynamic range, and, as static, whatever
/// of the label space those leave.
fn regions<'a>(
    blocks: impl IntoIterator<Item = (&'a String, &'a Block)>,
    retired: impl IntoIterator<Item = &'a LabelBlock>,
    dynamic: (u32, u32),
) -> Vec<Region> {
    let span = |b: &LabelBlock| (b.start < b.end).then(|| (b.start, b.end - 1));
    let mut regions = vec![Region::new(0, RESERVED_LAST, RegionKind::Reserved)];
    for (name, block) in blocks {
        for (kind, range) in [
            (RegionKind::Srgb, &block.global),
            (RegionKind::Srlb, &block.local),
        ] {
            if let Some((first, last)) = range.as_ref().and_then(span) {
                regions.push(Region {
                    block: Some(name.clone()),
                    ..Region::new(first, last, kind)
                });
            }
        }
    }
    regions.extend(
        retired
            .into_iter()
            .filter_map(span)
            .map(|(first, last)| Region::new(first, last, RegionKind::RetiredSrgb)),
    );
    regions.push(Region::new(dynamic.0, dynamic.1, RegionKind::Dynamic));

    let mut taken: Vec<(u32, u32)> = regions.iter().map(|r| (r.first, r.last)).collect();
    taken.sort();
    let mut next = 0;
    let mut gaps = Vec::new();
    for (first, last) in taken {
        if first > next {
            gaps.push(Region::new(next, first - 1, RegionKind::Static));
        }
        next = next.max(last.saturating_add(1));
    }
    if next < PLATFORM_LABELS {
        gaps.push(Region::new(next, PLATFORM_LABELS - 1, RegionKind::Static));
    }
    regions.extend(gaps);
    regions.sort_by_key(|r| (r.first, r.last));
    regions
}

/// The labels of `entries` inside `region`: those in blocks, how many
/// blocks, and the local labels.
fn allocated(region: &Region, entries: &[LabelEntry]) -> (u32, u32, u32) {
    let (mut block_labels, mut blocks, mut locals) = (0, 0, 0);
    for e in entries {
        let (first, last) = (e.first.max(region.first), e.last.min(region.last));
        if first > last {
            continue;
        }
        if e.kind == EntryKind::Block {
            block_labels += last - first + 1;
            blocks += 1;
        } else {
            locals += last - first + 1;
        }
    }
    (block_labels, blocks, locals)
}

fn plural(n: u32, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}

fn allocated_text((block_labels, blocks, locals): (u32, u32, u32)) -> String {
    let mut parts = Vec::new();
    if blocks > 0 {
        parts.push(format!(
            "{} in {}",
            plural(block_labels, "label"),
            plural(blocks, "block")
        ));
    }
    if locals > 0 {
        parts.push(plural(locals, "label"));
    }
    parts.join(", ")
}

fn range_text(first: u32, last: u32) -> String {
    if first == last {
        first.to_string()
    } else {
        format!("{first}-{last}")
    }
}

#[derive(Serialize)]
struct RegionJson {
    first: u32,
    last: u32,
    region: String,
    kind: RegionKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    block: Option<String>,
    allocated_labels: u32,
    allocated_blocks: u32,
}

fn render_range(regions: &[Region], entries: &[LabelEntry], json: bool) -> String {
    if json {
        let regions: Vec<RegionJson> = regions
            .iter()
            .map(|r| {
                let (block_labels, blocks, locals) = allocated(r, entries);
                RegionJson {
                    first: r.first,
                    last: r.last,
                    region: r.name(),
                    kind: r.kind,
                    block: r.block.clone(),
                    allocated_labels: block_labels + locals,
                    allocated_blocks: blocks,
                }
            })
            .collect();
        return serde_json::to_string_pretty(&serde_json::json!({ "regions": regions }))
            .unwrap_or_default();
    }
    let mut buf = String::new();
    writeln!(buf, "{:<16} {:<40} Allocated", "Range", "Region").unwrap();
    for r in regions {
        let line = format!(
            "{:<16} {:<40} {}",
            range_text(r.first, r.last),
            r.name(),
            allocated_text(allocated(r, entries))
        );
        writeln!(buf, "{}", line.trim_end()).unwrap();
    }
    buf
}

fn kind_text(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Block => "block",
        EntryKind::Local => "local",
        EntryKind::Configured => "configured SID",
    }
}

fn state_text(state: EntryState) -> &'static str {
    match state {
        EntryState::Held => "held",
        EntryState::Claimed => "claimed",
        EntryState::Releasing => "releasing",
        EntryState::Draining => "draining",
    }
}

#[derive(Serialize)]
struct EntryJson {
    first: u32,
    last: u32,
    owner: String,
    kind: &'static str,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_by: Option<String>,
}

fn entry_json(e: &LabelEntry, owner: &impl Fn(&Holder) -> String) -> EntryJson {
    EntryJson {
        first: e.first,
        last: e.last,
        owner: owner(&e.holder),
        kind: kind_text(e.kind),
        state: state_text(e.state),
        claimed_by: e.claimant.as_ref().map(owner),
    }
}

fn write_entries(buf: &mut String, entries: &[LabelEntry], owner: &impl Fn(&Holder) -> String) {
    writeln!(buf, "{:<14} {:<7} {:<15} State", "Label", "Owner", "Kind").unwrap();
    for e in entries {
        let mut state = state_text(e.state).to_string();
        if let Some(claimant) = &e.claimant {
            write!(state, ", claimed by {}", owner(claimant)).unwrap();
        }
        writeln!(
            buf,
            "{:<14} {:<7} {:<15} {}",
            range_text(e.first, e.last),
            owner(&e.holder),
            kind_text(e.kind),
            state
        )
        .unwrap();
    }
}

fn render_table(entries: &[LabelEntry], owner: &impl Fn(&Holder) -> String, json: bool) -> String {
    if json {
        let entries: Vec<EntryJson> = entries.iter().map(|e| entry_json(e, owner)).collect();
        return serde_json::to_string_pretty(&serde_json::json!({ "entries": entries }))
            .unwrap_or_default();
    }
    let mut buf = String::new();
    write_entries(&mut buf, entries, owner);
    buf
}

/// One label: the regions it is in (the dynamic range only when no SR
/// block is carved out of it there) and what holds it.
fn render_label(
    label: u32,
    regions: &[Region],
    entries: &[LabelEntry],
    owner: &impl Fn(&Holder) -> String,
    json: bool,
) -> String {
    let mut inside: Vec<&Region> = regions.iter().filter(|r| r.contains(label)).collect();
    if inside.iter().any(|r| r.kind != RegionKind::Dynamic) {
        inside.retain(|r| r.kind != RegionKind::Dynamic);
    }
    let held: Vec<LabelEntry> = entries
        .iter()
        .filter(|e| (e.first..=e.last).contains(&label))
        .cloned()
        .collect();
    let names: Vec<String> = inside.iter().map(|r| r.name()).collect();
    if json {
        let entries: Vec<EntryJson> = held.iter().map(|e| entry_json(e, owner)).collect();
        return serde_json::to_string_pretty(&serde_json::json!({
            "label": label,
            "regions": names,
            "entries": entries,
        }))
        .unwrap_or_default();
    }
    let mut buf = String::new();
    if names.is_empty() {
        writeln!(
            buf,
            "Label {label}: outside the label space (0-{})",
            PLATFORM_LABELS - 1
        )
        .unwrap();
        return buf;
    }
    writeln!(buf, "Label {label}: {}", names.join(" and ")).unwrap();
    if !held.is_empty() {
        write_entries(&mut buf, &held, owner);
        return buf;
    }
    let hint = if inside
        .iter()
        .any(|r| matches!(r.kind, RegionKind::Srgb | RegionKind::RetiredSrgb))
    {
        " (Prefix-SID labels: see show mpls ilm)"
    } else if inside.iter().any(|r| r.kind == RegionKind::Static) {
        " (static bindings: see show mpls ilm)"
    } else {
        ""
    };
    writeln!(buf, "  not allocated{hint}").unwrap();
    buf
}

/// The name of what holds a label: a block's protocol, or a pool
/// instance's protocol (its id once the instance is gone).
fn owner_name(rib: &Rib, holder: &Holder) -> String {
    match holder {
        Holder::Proto(proto) => proto.clone(),
        Holder::Instance(Some(id)) => rib
            .client_registry
            .subscriber(*id)
            .map(|s| s.proto.clone())
            .unwrap_or_else(|| id.to_string()),
        Holder::Instance(None) => "-".to_string(),
    }
}

/// The regions and entries as the RIB has them now.
fn snapshot(rib: &Rib) -> (Vec<Region>, Vec<LabelEntry>) {
    let space = rib.label_space.lock();
    let regions = regions(
        &rib.blocks,
        rib.retired_srgbs.iter().map(|(block, _)| block),
        space.dynamic_range(),
    );
    (regions, space.entries())
}

/// `show mpls label range`.
pub fn label_range_show(rib: &Rib, _args: Args, json: bool) -> String {
    let (regions, entries) = snapshot(rib);
    render_range(&regions, &entries, json)
}

/// `show mpls label table`.
pub fn label_table_show(rib: &Rib, _args: Args, json: bool) -> String {
    let (_, entries) = snapshot(rib);
    render_table(&entries, &|h| owner_name(rib, h), json)
}

/// `show mpls label table label <n>`.
pub fn label_table_label_show(rib: &Rib, mut args: Args, json: bool) -> String {
    let Some(label) = args.u32() else {
        return "% label required\n".to_string();
    };
    let (regions, entries) = snapshot(rib);
    render_label(label, &regions, &entries, &|h| owner_name(rib, h), json)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::rib::client::ProtoId;

    const DYNAMIC: (u32, u32) = (24000, 1048574);

    fn blocks(list: &[(&str, (u32, u32), (u32, u32))]) -> BTreeMap<String, Block> {
        list.iter()
            .map(|(name, (gs, gr), (ls, lr))| {
                (
                    name.to_string(),
                    Block {
                        global: Some(LabelBlock::new(*gs, *gr)),
                        local: Some(LabelBlock::new(*ls, *lr)),
                    },
                )
            })
            .collect()
    }

    fn default_block() -> BTreeMap<String, Block> {
        blocks(&[("default", (16000, 8000), (15000, 1000))])
    }

    fn instance(id: u32) -> Holder {
        Holder::Instance(Some(ProtoId::from_raw(id)))
    }

    fn entry(
        first: u32,
        last: u32,
        holder: Holder,
        kind: EntryKind,
        state: EntryState,
    ) -> LabelEntry {
        LabelEntry {
            first,
            last,
            holder,
            kind,
            state,
            claimant: None,
        }
    }

    /// Instance 1 is IS-IS, 2 OSPF.
    fn owner(holder: &Holder) -> String {
        match holder {
            Holder::Proto(proto) => proto.clone(),
            Holder::Instance(Some(id)) if *id == ProtoId::from_raw(1) => "isis".to_string(),
            Holder::Instance(Some(id)) if *id == ProtoId::from_raw(2) => "ospf".to_string(),
            Holder::Instance(_) => "-".to_string(),
        }
    }

    /// The labels the mockups were drawn from.
    fn entries() -> Vec<LabelEntry> {
        vec![
            entry(
                15000,
                15000,
                instance(1),
                EntryKind::Local,
                EntryState::Held,
            ),
            entry(
                15001,
                15001,
                instance(2),
                EntryKind::Configured,
                EntryState::Claimed,
            ),
            LabelEntry {
                claimant: Some(instance(2)),
                ..entry(
                    15002,
                    15002,
                    instance(1),
                    EntryKind::Local,
                    EntryState::Held,
                )
            },
            entry(
                15003,
                15003,
                instance(2),
                EntryKind::Local,
                EntryState::Releasing,
            ),
            entry(
                24000,
                25023,
                Holder::Proto("bgp".to_string()),
                EntryKind::Block,
                EntryState::Held,
            ),
        ]
    }

    #[test]
    fn the_range_shows_every_region_and_what_is_allocated_in_it() {
        let regions = regions(&default_block(), [], DYNAMIC);
        assert_eq!(
            render_range(&regions, &entries(), false),
            "\
Range            Region                                   Allocated
0-15             reserved (RFC 3032, RFC 7274)
16-14999         static
15000-15999      SRLB of segment-routing block default    4 labels
16000-23999      SRGB of segment-routing block default
24000-1048574    dynamic                                  1024 labels in 1 block
"
        );
    }

    /// Static is whatever the other regions leave, and a retired SRGB is a
    /// region of its own while it is held, overlapping the new one.
    #[test]
    fn static_regions_are_the_gaps_and_a_retired_srgb_is_shown() {
        let blocks = blocks(&[
            ("default", (18000, 4000), (15000, 1000)),
            ("core", (30000, 100), (1000, 100)),
        ]);
        let retired = [LabelBlock::new(16000, 8000)];
        let got: Vec<(u32, u32, RegionKind)> = regions(&blocks, &retired, DYNAMIC)
            .iter()
            .map(|r| (r.first, r.last, r.kind))
            .collect();
        assert_eq!(
            got,
            vec![
                (0, 15, RegionKind::Reserved),
                (16, 999, RegionKind::Static),
                (1000, 1099, RegionKind::Srlb),
                (1100, 14999, RegionKind::Static),
                (15000, 15999, RegionKind::Srlb),
                (16000, 23999, RegionKind::RetiredSrgb),
                (18000, 21999, RegionKind::Srgb),
                (24000, 1048574, RegionKind::Dynamic),
                (30000, 30099, RegionKind::Srgb),
            ]
        );
    }

    /// A dynamic range ending early (phase 6c) leaves static above it, down
    /// to a single label.
    #[test]
    fn labels_above_a_shorter_dynamic_range_are_static() {
        let last = regions(&default_block(), [], (24000, 1048573))
            .last()
            .map(|r| (r.first, r.last, r.kind));
        assert_eq!(last, Some((1048574, 1048574, RegionKind::Static)));
    }

    #[test]
    fn the_table_lists_every_allocation_with_owner_kind_and_state() {
        assert_eq!(
            render_table(&entries(), &owner, false),
            "\
Label          Owner   Kind            State
15000          isis    local           held
15001          ospf    configured SID  claimed
15002          isis    local           held, claimed by ospf
15003          ospf    local           releasing
24000-25023    bgp     block           held
"
        );
    }

    /// One label: its region, then what holds it, or where to look when
    /// nothing does.
    #[test]
    fn one_label_names_its_region_and_holder() {
        let blocks = blocks(&[
            ("default", (16000, 8000), (15000, 1000)),
            ("core", (30000, 100), (31000, 100)),
        ]);
        let regions = regions(&blocks, [], DYNAMIC);
        let show = |label| render_label(label, &regions, &entries(), &owner, false);
        assert_eq!(
            show(16005),
            "\
Label 16005: SRGB of segment-routing block default
  not allocated (Prefix-SID labels: see show mpls ilm)
"
        );
        assert_eq!(
            show(15002),
            "\
Label 15002: SRLB of segment-routing block default
Label          Owner   Kind            State
15002          isis    local           held, claimed by ospf
"
        );
        assert_eq!(
            show(24010),
            "\
Label 24010: dynamic
Label          Owner   Kind            State
24000-25023    bgp     block           held
"
        );
        assert_eq!(
            show(100),
            "Label 100: static\n  not allocated (static bindings: see show mpls ilm)\n"
        );
        assert_eq!(
            show(5),
            "Label 5: reserved (RFC 3032, RFC 7274)\n  not allocated\n"
        );
        // An SR block carved out of the dynamic range is the block's.
        assert_eq!(
            show(30050),
            "\
Label 30050: SRGB of segment-routing block core
  not allocated (Prefix-SID labels: see show mpls ilm)
"
        );
        assert_eq!(show(500000), "Label 500000: dynamic\n  not allocated\n");
        assert_eq!(
            show(1048575),
            "Label 1048575: outside the label space (0-1048574)\n"
        );
    }

    #[test]
    fn json_carries_the_same_facts() {
        let regions = regions(&default_block(), [], DYNAMIC);
        let range: serde_json::Value =
            serde_json::from_str(&render_range(&regions, &entries(), true)).unwrap();
        assert_eq!(
            range["regions"][2],
            serde_json::json!({
                "first": 15000,
                "last": 15999,
                "region": "SRLB of segment-routing block default",
                "kind": "srlb",
                "block": "default",
                "allocated_labels": 4,
                "allocated_blocks": 0,
            })
        );
        assert_eq!(range["regions"][4]["allocated_blocks"], 1);

        let table: serde_json::Value =
            serde_json::from_str(&render_table(&entries(), &owner, true)).unwrap();
        assert_eq!(
            table["entries"][2],
            serde_json::json!({
                "first": 15002,
                "last": 15002,
                "owner": "isis",
                "kind": "local",
                "state": "held",
                "claimed_by": "ospf",
            })
        );

        let label: serde_json::Value =
            serde_json::from_str(&render_label(16005, &regions, &entries(), &owner, true)).unwrap();
        assert_eq!(
            label,
            serde_json::json!({
                "label": 16005,
                "regions": ["SRGB of segment-routing block default"],
                "entries": [],
            })
        );
    }

    /// The callbacks read the RIB's own state: its blocks (the default one
    /// from the start), its label space, and its subscribers' names.
    #[tokio::test]
    async fn the_shows_read_the_ribs_label_space() {
        let rib = Rib::new(false).unwrap();
        let block = rib.label_space.lock().alloc("bgp", 128).expect("a block");
        let args = |list: &[&str]| Args(list.iter().map(|a| a.to_string()).collect());

        let range = label_range_show(&rib, args(&[]), false);
        assert!(
            range.contains("16000-23999      SRGB of segment-routing block default"),
            "{range}"
        );
        assert!(range.contains("128 labels in 1 block"), "{range}");

        let table = label_table_show(&rib, args(&[]), false);
        assert!(
            table.contains(&format!(
                "{}-{}    bgp     block",
                block.start,
                block.end - 1
            )),
            "{table}"
        );

        let label = label_table_label_show(&rib, args(&["15000"]), false);
        assert_eq!(
            label,
            "Label 15000: SRLB of segment-routing block default\n  not allocated\n"
        );
    }

    /// A pool's label is shown under its instance's protocol, and under
    /// the instance's id once it is gone.
    #[tokio::test]
    async fn a_local_label_is_shown_under_its_instances_protocol() {
        let mut rib = Rib::new(false).unwrap();
        let (rib_rx_tx, _rib_rx) = tokio::sync::mpsc::unbounded_channel();
        let (inbound_tx, _inbound_rx) = tokio::sync::mpsc::unbounded_channel();
        let id = ProtoId::from_raw(7);
        rib.client_registry
            .register_with_id(id, "ospf", rib_rx_tx, 0, false);
        let client = crate::rib::client::RibClient::new(inbound_tx, id);
        let mut pool = rib.label_space.pool_for(15000, 15999, &client);
        assert_eq!(pool.allocate(), Some(15000));
        let args = || Args(Default::default());

        let table = label_table_show(&rib, args(), false);
        assert!(
            table.contains("15000          ospf    local           held"),
            "{table}"
        );

        rib.client_registry = crate::rib::client::ClientRegistry::new();
        let table = label_table_show(&rib, args(), false);
        assert!(
            table.contains("15000          proto#7 local           held"),
            "{table}"
        );
    }
}
