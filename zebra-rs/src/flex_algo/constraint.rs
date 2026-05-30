use std::collections::BTreeSet;

use packet_utils::ExtAdminGroup;

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
pub fn link_passes_fad<A: AffinityBits>(
    affinity: Option<&ExtAdminGroup>,
    entry: &FlexAlgoEntry,
    am: &A,
) -> bool {
    let exclude = local_link_affinity(&entry.exclude_any, am);
    let include_any = local_link_affinity(&entry.include_any, am);
    let include_all = local_link_affinity(&entry.include_all, am);

    let empty = ExtAdminGroup::default();
    let bitmap = affinity.unwrap_or(&empty);

    if !ext_admin_group_intersection(&exclude, bitmap).is_empty() {
        return false;
    }
    if !include_any.words.iter().all(|w| *w == 0)
        && ext_admin_group_intersection(&include_any, bitmap).is_empty()
    {
        return false;
    }
    if !ext_admin_group_contains(bitmap, &include_all) {
        return false;
    }
    true
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

    #[test]
    fn local_link_affinity_resolves_names_to_bits() {
        let am = affinity_map(&["red", "blue", "green"]);
        let g = local_link_affinity(&affinity_set(&["red", "green"]), &am);
        assert!(g.get(0));
        assert!(!g.get(1));
        assert!(g.get(2));
    }
}
