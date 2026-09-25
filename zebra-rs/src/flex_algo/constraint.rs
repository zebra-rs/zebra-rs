use std::collections::BTreeSet;

use packet_utils::ExtAdminGroup;

use super::entry::FadMetricType;
#[cfg(test)]
use super::entry::FlexAlgoEntry;

/// Resolves an affinity (admin-group) name to its RFC 7308 bit
/// position. Implemented by each protocol's affinity-map table
/// (`isis::affinity_map::AffinityMap` today) so the constraint engine
/// stays protocol-neutral.
pub trait AffinityBits {
    fn affinity_bit(&self, name: &str) -> Option<u16>;
}

/// Resolve a set of affinity names to an `ExtAdminGroup` bitmap via
/// `am`. Names with no matching entry are silently dropped
/// (best-effort: the wire form would not have carried that bit
/// either).
///
/// Used by per-algo SPF to derive the bitmap for our own local edges,
/// since peer-ingested link affinity excludes the local node.
pub fn local_link_affinity<A: AffinityBits>(affinity: &BTreeSet<String>, am: &A) -> ExtAdminGroup {
    let mut g = ExtAdminGroup::default();
    for name in affinity {
        if let Some(bit) = am.affinity_bit(name) {
            g.set(bit);
        }
    }
    g
}

/// Apply the RFC 9350 §6 link-attribute constraints from `entry`
/// against `affinity`. Returns true when the link is admissible for
/// the algorithm's SPF graph.
///
/// Tests only: this router's configured definition is not what it
/// computes with. The path computation applies the winning definition's
/// constraints (RFC 9350 §5.3) through [`link_prune_reason`]; the tests
/// below exercise those rules through this entry-shaped front.
///
/// `affinity = None` means the source did not advertise an admin-group
/// bitmap for this neighbor — treated as the empty bitmap (every bit
/// = 0). That's the right default for peers that simply haven't
/// configured admin-groups: include-any with a non-empty constraint
/// rejects them, which matches the §6 "no link attribute" reading.
///
/// Constraint semantics:
///   - **exclude-any**: link fails if any of the FAD's excluded bits
///     is set in `affinity` (intersection non-empty).
///   - **include-any**: when the FAD lists any bit here, the link
///     must have at least one of them set (intersection non-empty).
///     Empty constraint = no requirement.
///   - **include-all**: every bit in the FAD's constraint must be set
///     on the link.
///
/// Name resolution failures (a constraint name not in `am`) are
/// silently dropped — the wire form would not have carried that bit
/// anyway.
#[cfg(test)]
pub fn link_passes_fad<A: AffinityBits>(
    affinity: Option<&ExtAdminGroup>,
    entry: &FlexAlgoEntry,
    am: &A,
) -> bool {
    let constraints = FadConstraints {
        metric_type: entry.metric_type.unwrap_or(FadMetricType::Igp),
        exclude_any: local_link_affinity(&entry.exclude_any, am),
        include_any: local_link_affinity(&entry.include_any, am),
        include_all: local_link_affinity(&entry.include_all, am),
        max_link_loss: None,
    };
    let link = LinkAttrs {
        affinity: affinity.cloned(),
        loss: None,
    };
    link_passes_constraints(&link, &constraints)
}

/// A Flexible Algorithm Definition resolved to what the path computation
/// needs: the metric-type, the three admin-group rules as bitmaps, and the
/// maximum link loss. It is what a *winning* FAD (RFC 9350 §5.3) reduces
/// to once every element in it is known to be supported, so the
/// computation reads the definition every participant agreed on, not this
/// router's config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FadConstraints {
    pub metric_type: FadMetricType,
    pub exclude_any: ExtAdminGroup,
    pub include_any: ExtAdminGroup,
    pub include_all: ExtAdminGroup,
    /// Exclude Maximum Link Loss (draft-ietf-lsr-flex-algo-link-loss), in
    /// RFC 8570 units of 0.000003 %.
    pub max_link_loss: Option<u32>,
}

/// A link's attributes as the Flexible Algorithm application sees them —
/// for a peer's link, as RFC 9479 §4.2 selects them from its
/// advertisement; for this router's own, what it advertises.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkAttrs {
    /// The Extended Admin Group; `None` is the empty bitmap, which fails a
    /// non-empty include-any or include-all and passes any exclude-any.
    pub affinity: Option<ExtAdminGroup>,
    /// Unidirectional link loss (RFC 8570 §4.4) in its raw 24-bit units;
    /// `None` when none is advertised.
    pub loss: Option<u32>,
}

/// Why a link is pruned from a Flexible Algorithm's topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pruned {
    /// RFC 9350 §13 rules 1, 3 or 4: exclude-any, include-any or
    /// include-all.
    Affinity,
    /// Its advertised loss exceeds the definition's maximum.
    LinkLoss { loss: u32, max: u32 },
}

impl std::fmt::Display for Pruned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pruned::Affinity => write!(f, "affinity"),
            Pruned::LinkLoss { loss, max } => write!(
                f,
                "link loss {} ({loss}) exceeds {} ({max})",
                LossPercent(*loss),
                LossPercent(*max)
            ),
        }
    }
}

/// An RFC 8570 loss value rendered as the percentage it encodes. One unit
/// is 0.000003 %, three micro-percent, so the rendering is exact.
pub struct LossPercent(pub u32);

impl std::fmt::Display for LossPercent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let micro = u64::from(self.0) * 3;
        write!(f, "{}.{:06}%", micro / 1_000_000, micro % 1_000_000)
    }
}

/// The pruning rules a supported definition carries, applied to one link
/// (RFC 9350 §13 rules 1, 3 and 4, then the link-loss rule), or `None`
/// when the link stays in the algorithm's topology.
///
/// The loss rule prunes a link whose advertised loss is strictly greater
/// than the maximum, and keeps one that advertises none: "if a link does
/// not advertise the link loss but the FAD contains the FAEML sub-TLV, the
/// link MUST NOT be excluded". Both are raw integers, compared as numbers
/// — 0xFFFFFF included — so every router reaches the same answer. No
/// hysteresis or damping: pruning is a pure function of the LSDB, or two
/// routers that saw the same advertisements at different moments prune
/// differently and Flex-Algo forwarding loops. Stability belongs to the
/// advertiser.
pub fn link_prune_reason(link: &LinkAttrs, c: &FadConstraints) -> Option<Pruned> {
    let empty = ExtAdminGroup::default();
    let bitmap = link.affinity.as_ref().unwrap_or(&empty);

    if !ext_admin_group_intersection(&c.exclude_any, bitmap).is_empty() {
        return Some(Pruned::Affinity);
    }
    if !c.include_any.words.iter().all(|w| *w == 0)
        && ext_admin_group_intersection(&c.include_any, bitmap).is_empty()
    {
        return Some(Pruned::Affinity);
    }
    if !ext_admin_group_contains(bitmap, &c.include_all) {
        return Some(Pruned::Affinity);
    }
    if let (Some(max), Some(loss)) = (c.max_link_loss, link.loss)
        && loss > max
    {
        return Some(Pruned::LinkLoss { loss, max });
    }
    None
}

/// Whether a link stays in the algorithm's topology — see
/// [`link_prune_reason`].
#[cfg(test)]
pub fn link_passes_constraints(link: &LinkAttrs, c: &FadConstraints) -> bool {
    link_prune_reason(link, c).is_none()
}

/// Bitwise AND of two `ExtAdminGroup` bitmaps. Returned bitmap is
/// length min(a, b) — trailing zero words from a longer operand do
/// not contribute set bits.
fn ext_admin_group_intersection(a: &ExtAdminGroup, b: &ExtAdminGroup) -> ExtAdminGroup {
    let len = a.words.len().min(b.words.len());
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        out.push(a.words[i] & b.words[i]);
    }
    ExtAdminGroup { words: out }
}

/// True iff every set bit in `needed` is also set in `bitmap`.
/// Trailing words past `bitmap.words.len()` in `needed` must be zero.
fn ext_admin_group_contains(bitmap: &ExtAdminGroup, needed: &ExtAdminGroup) -> bool {
    for (i, w) in needed.words.iter().enumerate() {
        let have = bitmap.words.get(i).copied().unwrap_or(0);
        if *w & !have != 0 {
            return false;
        }
    }
    true
}

/// True iff `g` has no set bits.
trait ExtAdminGroupExt {
    fn is_empty(&self) -> bool;
}

impl ExtAdminGroupExt for ExtAdminGroup {
    fn is_empty(&self) -> bool {
        self.words.iter().all(|w| *w == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Minimal `AffinityBits` impl for tests — maps names to bit
    /// positions without pulling in any protocol's affinity table.
    struct MockAffinity(BTreeMap<String, u16>);

    impl AffinityBits for MockAffinity {
        fn affinity_bit(&self, name: &str) -> Option<u16> {
            self.0.get(name).copied()
        }
    }

    /// Build a `MockAffinity` assigning each name its own bit starting
    /// at 0 (name[0] -> bit 0, name[1] -> bit 1, ...).
    fn affinity_map(names: &[&str]) -> MockAffinity {
        MockAffinity(
            names
                .iter()
                .enumerate()
                .map(|(i, n)| ((*n).to_string(), i as u16))
                .collect(),
        )
    }

    fn affinity_set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    /// Build an `ExtAdminGroup` from a list of bit positions.
    fn admin_group(bits: &[u16]) -> ExtAdminGroup {
        let mut g = ExtAdminGroup::default();
        for b in bits {
            g.set(*b);
        }
        g
    }

    fn fad_entry(
        exclude_any: &[&str],
        include_any: &[&str],
        include_all: &[&str],
    ) -> FlexAlgoEntry {
        FlexAlgoEntry {
            exclude_any: affinity_set(exclude_any),
            include_any: affinity_set(include_any),
            include_all: affinity_set(include_all),
            ..Default::default()
        }
    }

    #[test]
    fn link_passes_fad_no_constraints_accepts_anything() {
        let am = affinity_map(&["red"]);
        let entry = fad_entry(&[], &[], &[]);
        assert!(link_passes_fad(None, &entry, &am));
        let g = admin_group(&[0]);
        assert!(link_passes_fad(Some(&g), &entry, &am));
    }

    #[test]
    fn link_passes_fad_exclude_any_drops_link_with_excluded_bit() {
        let am = affinity_map(&["red", "blue"]);
        let entry = fad_entry(&["red"], &[], &[]);
        let red = admin_group(&[0]);
        let blue = admin_group(&[1]);
        assert!(!link_passes_fad(Some(&red), &entry, &am));
        assert!(link_passes_fad(Some(&blue), &entry, &am));
        // Missing affinity = empty bitmap = no excluded bit set.
        assert!(link_passes_fad(None, &entry, &am));
    }

    #[test]
    fn link_passes_fad_include_any_requires_at_least_one_bit() {
        let am = affinity_map(&["red", "blue", "green"]);
        let entry = fad_entry(&[], &["red", "blue"], &[]);
        // No bits set → fails include-any when constraint is non-empty.
        assert!(!link_passes_fad(None, &entry, &am));
        // Unrelated bit only → still fails.
        let green = admin_group(&[2]);
        assert!(!link_passes_fad(Some(&green), &entry, &am));
        // One of the required bits → passes.
        let red = admin_group(&[0]);
        assert!(link_passes_fad(Some(&red), &entry, &am));
        // Both required bits → passes.
        let red_blue = admin_group(&[0, 1]);
        assert!(link_passes_fad(Some(&red_blue), &entry, &am));
    }

    #[test]
    fn link_passes_fad_include_all_requires_every_bit() {
        let am = affinity_map(&["red", "blue", "green"]);
        let entry = fad_entry(&[], &[], &["red", "blue"]);
        // Empty bitmap → missing both → fails.
        assert!(!link_passes_fad(None, &entry, &am));
        // Only one of the required bits → fails.
        let red = admin_group(&[0]);
        assert!(!link_passes_fad(Some(&red), &entry, &am));
        // Both required bits → passes.
        let red_blue = admin_group(&[0, 1]);
        assert!(link_passes_fad(Some(&red_blue), &entry, &am));
        // Superset (all required + extra) → still passes.
        let red_blue_green = admin_group(&[0, 1, 2]);
        assert!(link_passes_fad(Some(&red_blue_green), &entry, &am));
    }

    #[test]
    fn link_passes_fad_combined_constraints_all_must_pass() {
        // exclude red, include-any {blue, green}, include-all {blue}
        let am = affinity_map(&["red", "blue", "green"]);
        let entry = fad_entry(&["red"], &["blue", "green"], &["blue"]);
        // red present → exclude trips first.
        let red_blue = admin_group(&[0, 1]);
        assert!(!link_passes_fad(Some(&red_blue), &entry, &am));
        // blue alone → satisfies include-any (blue ∈ {blue, green}) and
        // include-all ({blue} ⊆ {blue}).
        let blue = admin_group(&[1]);
        assert!(link_passes_fad(Some(&blue), &entry, &am));
        // green alone → satisfies include-any but not include-all.
        let green = admin_group(&[2]);
        assert!(!link_passes_fad(Some(&green), &entry, &am));
    }

    #[test]
    fn link_passes_fad_unresolved_constraint_names_silently_drop() {
        // FAD references "purple" which isn't in the affinity-map; the
        // bit cannot be encoded into the local bitmap, so an include-
        // all on it alone reduces to an empty requirement → passes.
        let am = affinity_map(&["red"]);
        let entry = fad_entry(&[], &[], &["purple"]);
        assert!(link_passes_fad(None, &entry, &am));
        let red = admin_group(&[0]);
        assert!(link_passes_fad(Some(&red), &entry, &am));
    }

    fn with_max(max: Option<u32>) -> FadConstraints {
        FadConstraints {
            max_link_loss: max,
            ..Default::default()
        }
    }

    fn lossy(loss: Option<u32>) -> LinkAttrs {
        LinkAttrs {
            affinity: None,
            loss,
        }
    }

    /// draft-ietf-lsr-flex-algo-link-loss: pruned only when the loss
    /// *exceeds* the maximum; kept when equal, below, or not advertised;
    /// every value compared as a number — 0xFFFFFF too.
    #[test]
    fn link_loss_pruning_truth_table() {
        let max = 1_666_667;
        for (loss, pruned) in [
            (Some(max + 1), true),
            (Some(max), false),
            (Some(max - 1), false),
            (Some(0), false),
            (None, false),
            (Some(0x00FF_FFFF), true),
        ] {
            assert_eq!(
                link_prune_reason(&lossy(loss), &with_max(Some(max))),
                pruned.then(|| Pruned::LinkLoss {
                    loss: loss.unwrap(),
                    max
                }),
                "{loss:?}"
            );
        }
        // No constraint, no pruning, however lossy.
        assert_eq!(
            link_prune_reason(&lossy(Some(0x00FF_FFFF)), &with_max(None)),
            None
        );
        // Zero keeps only loss-free links — and links advertising none.
        assert!(link_passes_constraints(&lossy(Some(0)), &with_max(Some(0))));
        assert!(!link_passes_constraints(
            &lossy(Some(1)),
            &with_max(Some(0))
        ));
        assert!(link_passes_constraints(&lossy(None), &with_max(Some(0))));
        // The ceiling RFC 8570 can express is compared like any value.
        assert!(link_passes_constraints(
            &lossy(Some(0x00FF_FFFE)),
            &with_max(Some(0x00FF_FFFE))
        ));
    }

    /// Affinity is checked first; a link failing both is reported for it.
    #[test]
    fn affinity_prunes_before_loss() {
        let c = FadConstraints {
            exclude_any: admin_group(&[3]),
            max_link_loss: Some(10),
            ..Default::default()
        };
        let link = LinkAttrs {
            affinity: Some(admin_group(&[3])),
            loss: Some(11),
        };
        assert_eq!(link_prune_reason(&link, &c), Some(Pruned::Affinity));
    }

    #[test]
    fn loss_renders_as_the_percentage_it_encodes() {
        assert_eq!(LossPercent(1_666_667).to_string(), "5.000001%");
        assert_eq!(LossPercent(0x00FF_FFFE).to_string(), "50.331642%");
        assert_eq!(LossPercent(0).to_string(), "0.000000%");
        assert_eq!(
            Pruned::LinkLoss {
                loss: 2_500_000,
                max: 1_666_667
            }
            .to_string(),
            "link loss 7.500000% (2500000) exceeds 5.000001% (1666667)"
        );
    }

    #[test]
    fn local_link_affinity_resolves_names_to_bits() {
        let am = affinity_map(&["red", "blue", "green"]);
        let g = local_link_affinity(&affinity_set(&["red", "green"]), &am);
        assert!(g.get(0));
        assert!(!g.get(1));
        assert!(g.get(2));
    }
}
