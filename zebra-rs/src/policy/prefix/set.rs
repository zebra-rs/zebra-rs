use std::collections::BTreeMap;
use std::collections::btree_map;

use ipnet::IpNet;

use super::trie::{PrefixTrie, ipnet_to_bits, truncate_prefix};

#[derive(Default, Clone, Debug)]
pub struct PrefixSet {
    prefixes: BTreeMap<IpNet, PrefixSetEntry>,
    trie4: PrefixTrie,
    trie6: PrefixTrie,
    pub delete: bool,
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct PrefixSetEntry {
    pub le: Option<u8>,
    pub eq: Option<u8>,
    pub ge: Option<u8>,
}

impl PartialEq for PrefixSet {
    fn eq(&self, other: &Self) -> bool {
        self.prefixes == other.prefixes && self.delete == other.delete
    }
}

impl PrefixSet {
    /// Get a mutable reference to the entry for `prefix`, creating a
    /// default entry (and registering the prefix in the trie) if
    /// missing.
    pub fn entry(&mut self, prefix: IpNet) -> &mut PrefixSetEntry {
        match self.prefixes.entry(prefix) {
            btree_map::Entry::Occupied(o) => o.into_mut(),
            btree_map::Entry::Vacant(v) => {
                let (bits, len, is_v4) = ipnet_to_bits(prefix);
                let trie = if is_v4 {
                    &mut self.trie4
                } else {
                    &mut self.trie6
                };
                trie.insert(bits, len);
                v.insert(PrefixSetEntry::default())
            }
        }
    }

    /// Insert (or replace) the entry for `prefix`. Returns the
    /// previous entry if one existed.
    #[allow(dead_code)]
    pub fn insert(&mut self, prefix: IpNet, entry: PrefixSetEntry) -> Option<PrefixSetEntry> {
        let prev = self.prefixes.insert(prefix, entry);
        if prev.is_none() {
            let (bits, len, is_v4) = ipnet_to_bits(prefix);
            let trie = if is_v4 {
                &mut self.trie4
            } else {
                &mut self.trie6
            };
            trie.insert(bits, len);
        }
        prev
    }

    /// Remove `prefix` from the set, returning the removed entry.
    pub fn remove(&mut self, prefix: &IpNet) -> Option<PrefixSetEntry> {
        let removed = self.prefixes.remove(prefix);
        if removed.is_some() {
            let (bits, len, is_v4) = ipnet_to_bits(*prefix);
            let trie = if is_v4 {
                &mut self.trie4
            } else {
                &mut self.trie6
            };
            trie.remove(bits, len);
        }
        removed
    }

    /// Get a mutable reference to an existing entry without altering
    /// the set membership.
    pub fn get_mut(&mut self, prefix: &IpNet) -> Option<&mut PrefixSetEntry> {
        self.prefixes.get_mut(prefix)
    }

    pub fn iter(&self) -> btree_map::Iter<'_, IpNet, PrefixSetEntry> {
        self.prefixes.iter()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.prefixes.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }

    #[allow(dead_code)]
    pub fn contains_prefix(&self, prefix: &IpNet) -> bool {
        self.prefixes.contains_key(prefix)
    }

    /// Check if the given IPv4 or IPv6 network matches any prefix in this set.
    ///
    /// A network matches if:
    /// 1. Its network address is contained within a prefix in the set
    /// 2. Its prefix length satisfies the filtering criteria (le, eq, ge) of that prefix
    pub fn matches(&self, net: impl Into<IpNet> + Copy) -> bool {
        let net: IpNet = net.into();
        let (bits, qlen, is_v4) = ipnet_to_bits(net);
        let trie = if is_v4 { &self.trie4 } else { &self.trie6 };

        let mut found = false;
        trie.walk_enclosing(bits, qlen, |depth| {
            let key = truncate_prefix(net, depth);
            if let Some(entry) = self.prefixes.get(&key)
                && entry_passes(entry, qlen)
            {
                found = true;
                return true;
            }
            false
        });
        found
    }
}

fn entry_passes(entry: &PrefixSetEntry, qlen: u8) -> bool {
    if let Some(le) = entry.le
        && qlen > le
    {
        return false;
    }
    if let Some(eq) = entry.eq
        && qlen != eq
    {
        return false;
    }
    if let Some(ge) = entry.ge
        && qlen < ge
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_matches_ipv4_no_constraints() {
        let mut prefix_set = PrefixSet::default();
        let prefix = IpNet::from_str("10.0.0.0/8").unwrap();
        prefix_set.insert(prefix, PrefixSetEntry::default());

        // Should match any prefix length within 10.0.0.0/8
        let net1 = IpNet::from_str("10.1.0.0/16").unwrap();
        let net2 = IpNet::from_str("10.1.2.0/24").unwrap();
        let net3 = IpNet::from_str("10.0.0.0/8").unwrap();

        assert!(prefix_set.matches(net1));
        assert!(prefix_set.matches(net2));
        assert!(prefix_set.matches(net3));

        // Should not match outside the prefix
        let net4 = IpNet::from_str("192.168.1.0/24").unwrap();
        assert!(!prefix_set.matches(net4));
    }

    #[test]
    fn test_matches_ipv4_with_le_constraint() {
        let mut prefix_set = PrefixSet::default();
        let prefix = IpNet::from_str("10.0.0.0/8").unwrap();
        prefix_set.insert(
            prefix,
            PrefixSetEntry {
                le: Some(24),
                eq: None,
                ge: None,
            },
        );

        // Should match prefix lengths <= 24
        let net1 = IpNet::from_str("10.1.0.0/16").unwrap();
        let net2 = IpNet::from_str("10.1.2.0/24").unwrap();
        assert!(prefix_set.matches(net1));
        assert!(prefix_set.matches(net2));

        // Should not match prefix length > 24
        let net3 = IpNet::from_str("10.1.2.0/25").unwrap();
        assert!(!prefix_set.matches(net3));
    }

    #[test]
    fn test_matches_ipv4_with_ge_constraint() {
        let mut prefix_set = PrefixSet::default();
        let prefix = IpNet::from_str("10.0.0.0/8").unwrap();
        prefix_set.insert(
            prefix,
            PrefixSetEntry {
                le: None,
                eq: None,
                ge: Some(16),
            },
        );

        // Should match prefix lengths >= 16
        let net1 = IpNet::from_str("10.1.0.0/16").unwrap();
        let net2 = IpNet::from_str("10.1.2.0/24").unwrap();
        assert!(prefix_set.matches(net1));
        assert!(prefix_set.matches(net2));

        // Should not match prefix length < 16
        let net3 = IpNet::from_str("10.0.0.0/8").unwrap();
        assert!(!prefix_set.matches(net3));
    }

    #[test]
    fn test_matches_ipv4_with_eq_constraint() {
        let mut prefix_set = PrefixSet::default();
        let prefix = IpNet::from_str("10.0.0.0/8").unwrap();
        prefix_set.insert(
            prefix,
            PrefixSetEntry {
                le: None,
                eq: Some(24),
                ge: None,
            },
        );

        // Should match only prefix length == 24
        let net1 = IpNet::from_str("10.1.2.0/24").unwrap();
        assert!(prefix_set.matches(net1));

        // Should not match other prefix lengths
        let net2 = IpNet::from_str("10.1.0.0/16").unwrap();
        let net3 = IpNet::from_str("10.1.2.0/25").unwrap();
        assert!(!prefix_set.matches(net2));
        assert!(!prefix_set.matches(net3));
    }

    #[test]
    fn test_matches_ipv4_with_range_constraints() {
        let mut prefix_set = PrefixSet::default();
        let prefix = IpNet::from_str("10.0.0.0/8").unwrap();
        prefix_set.insert(
            prefix,
            PrefixSetEntry {
                le: Some(24),
                eq: None,
                ge: Some(16),
            },
        );

        // Should match prefix lengths in range [16, 24]
        let net1 = IpNet::from_str("10.1.0.0/16").unwrap();
        let net2 = IpNet::from_str("10.1.2.0/20").unwrap();
        let net3 = IpNet::from_str("10.1.2.0/24").unwrap();
        assert!(prefix_set.matches(net1));
        assert!(prefix_set.matches(net2));
        assert!(prefix_set.matches(net3));

        // Should not match outside the range
        let net4 = IpNet::from_str("10.0.0.0/8").unwrap();
        let net5 = IpNet::from_str("10.1.2.0/25").unwrap();
        assert!(!prefix_set.matches(net4));
        assert!(!prefix_set.matches(net5));
    }

    #[test]
    fn test_matches_ipv6() {
        let mut prefix_set = PrefixSet::default();
        let prefix = IpNet::from_str("2001:db8::/32").unwrap();
        prefix_set.insert(
            prefix,
            PrefixSetEntry {
                le: Some(64),
                eq: None,
                ge: Some(48),
            },
        );

        // Should match IPv6 prefixes in range [48, 64]
        let net1 = IpNet::from_str("2001:db8::/48").unwrap();
        let net2 = IpNet::from_str("2001:db8:1::/56").unwrap();
        let net3 = IpNet::from_str("2001:db8:1:2::/64").unwrap();
        assert!(prefix_set.matches(net1));
        assert!(prefix_set.matches(net2));
        assert!(prefix_set.matches(net3));

        // Should not match outside the range
        let net4 = IpNet::from_str("2001:db8::/32").unwrap();
        let net5 = IpNet::from_str("2001:db8:1:2::/80").unwrap();
        assert!(!prefix_set.matches(net4));
        assert!(!prefix_set.matches(net5));

        // Should not match different IPv6 prefix
        let net6 = IpNet::from_str("2001:db9::/48").unwrap();
        assert!(!prefix_set.matches(net6));
    }

    #[test]
    fn test_matches_multiple_prefixes() {
        let mut prefix_set = PrefixSet::default();

        // Add first prefix with constraints
        let prefix1 = IpNet::from_str("10.0.0.0/8").unwrap();
        prefix_set.insert(
            prefix1,
            PrefixSetEntry {
                le: Some(24),
                eq: None,
                ge: Some(16),
            },
        );

        // Add second prefix with different constraints
        let prefix2 = IpNet::from_str("192.168.0.0/16").unwrap();
        prefix_set.insert(
            prefix2,
            PrefixSetEntry {
                le: None,
                eq: Some(24),
                ge: None,
            },
        );

        // Should match first prefix rules
        let net1 = IpNet::from_str("10.1.0.0/16").unwrap();
        assert!(prefix_set.matches(net1));

        // Should match second prefix rules
        let net2 = IpNet::from_str("192.168.1.0/24").unwrap();
        assert!(prefix_set.matches(net2));

        // Should not match either
        let net3 = IpNet::from_str("172.16.0.0/12").unwrap();
        assert!(!prefix_set.matches(net3));
    }

    #[test]
    fn test_empty_prefix_set() {
        let prefix_set = PrefixSet::default();

        let net = IpNet::from_str("10.1.0.0/16").unwrap();
        assert!(!prefix_set.matches(net));
    }

    #[test]
    fn test_prefix_containment() {
        let mut prefix_set = PrefixSet::default();
        let prefix = IpNet::from_str("10.1.0.0/16").unwrap();
        prefix_set.insert(prefix, PrefixSetEntry::default());

        // Should match - contained within 10.1.0.0/16
        let net1 = IpNet::from_str("10.1.2.0/24").unwrap();
        assert!(prefix_set.matches(net1));

        // Should not match - not contained (different /16)
        let net2 = IpNet::from_str("10.2.0.0/24").unwrap();
        assert!(!prefix_set.matches(net2));

        // Should match - exact match
        let net3 = IpNet::from_str("10.1.0.0/16").unwrap();
        assert!(prefix_set.matches(net3));
    }

    #[test]
    fn test_overlapping_enclosing_prefixes_pick_first_passing() {
        // /8 has le=15 (rejects /24); /16 has no constraint (accepts).
        // Trie walk visits /8 then /16; the matcher must keep walking
        // past the /8 rejection and accept on /16.
        let mut prefix_set = PrefixSet::default();
        prefix_set.insert(
            IpNet::from_str("10.0.0.0/8").unwrap(),
            PrefixSetEntry {
                le: Some(15),
                eq: None,
                ge: None,
            },
        );
        prefix_set.insert(
            IpNet::from_str("10.1.0.0/16").unwrap(),
            PrefixSetEntry::default(),
        );

        let q = IpNet::from_str("10.1.2.0/24").unwrap();
        assert!(prefix_set.matches(q));
    }

    #[test]
    fn test_remove_unindexes() {
        let mut prefix_set = PrefixSet::default();
        let prefix = IpNet::from_str("10.0.0.0/8").unwrap();
        prefix_set.insert(prefix, PrefixSetEntry::default());

        let q = IpNet::from_str("10.1.0.0/16").unwrap();
        assert!(prefix_set.matches(q));

        prefix_set.remove(&prefix);
        assert!(!prefix_set.matches(q));
    }

    #[test]
    fn test_v4_and_v6_isolated() {
        // The IPv4 trie must not be consulted for IPv6 queries and
        // vice versa, even when the bit patterns look similar.
        let mut prefix_set = PrefixSet::default();
        prefix_set.insert(
            IpNet::from_str("10.0.0.0/8").unwrap(),
            PrefixSetEntry::default(),
        );
        let v6_q = IpNet::from_str("a00::/8").unwrap();
        assert!(!prefix_set.matches(v6_q));
    }

    #[test]
    fn test_zero_prefix_root_matches_anything() {
        let mut prefix_set = PrefixSet::default();
        prefix_set.insert(
            IpNet::from_str("0.0.0.0/0").unwrap(),
            PrefixSetEntry::default(),
        );
        for net in &["10.0.0.0/8", "0.0.0.0/0", "192.168.1.1/32"] {
            assert!(prefix_set.matches(IpNet::from_str(net).unwrap()));
        }
    }

    /// Reference implementation matching the previous O(n) linear
    /// scan, kept here so the benchmark below compares apples-to-
    /// apples on identical data.
    fn matches_linear(set: &PrefixSet, net: IpNet) -> bool {
        let qlen = net.prefix_len();
        for (prefix, entry) in set.iter() {
            if !prefix.contains(&net) {
                continue;
            }
            if let Some(le) = entry.le
                && qlen > le
            {
                continue;
            }
            if let Some(eq) = entry.eq
                && qlen != eq
            {
                continue;
            }
            if let Some(ge) = entry.ge
                && qlen < ge
            {
                continue;
            }
            return true;
        }
        false
    }

    /// Run with: `cargo test --release --bin zebra-rs -- --ignored
    /// --nocapture bench_matches_vs_linear_scan`
    #[test]
    #[ignore]
    fn bench_matches_vs_linear_scan() {
        use std::net::Ipv4Addr;
        use std::time::Instant;

        for &n in &[100usize, 1_000, 10_000, 100_000] {
            // Build a set of /24s spread across the IPv4 space.
            let mut set = PrefixSet::default();
            for i in 0..n {
                let a = ((i >> 16) & 0xff) as u8;
                let b = ((i >> 8) & 0xff) as u8;
                let c = (i & 0xff) as u8;
                let prefix: IpNet = ipnet::Ipv4Net::new(Ipv4Addr::new(a, b, c, 0), 24)
                    .unwrap()
                    .into();
                set.insert(prefix, PrefixSetEntry::default());
            }

            // Pick a deterministic mix of hits and misses.
            let queries: Vec<IpNet> = (0..10_000)
                .map(|i| {
                    let a = ((i * 7919) & 0xff) as u8;
                    let b = ((i * 31) & 0xff) as u8;
                    let c = ((i * 17) & 0xff) as u8;
                    ipnet::Ipv4Net::new(Ipv4Addr::new(a, b, c, 1), 32)
                        .unwrap()
                        .into()
                })
                .collect();

            let start = Instant::now();
            let mut hits_trie = 0usize;
            for q in &queries {
                if set.matches(*q) {
                    hits_trie += 1;
                }
            }
            let trie_elapsed = start.elapsed();

            let start = Instant::now();
            let mut hits_linear = 0usize;
            for q in &queries {
                if matches_linear(&set, *q) {
                    hits_linear += 1;
                }
            }
            let linear_elapsed = start.elapsed();

            assert_eq!(hits_trie, hits_linear, "trie and linear must agree");
            let speedup = linear_elapsed.as_nanos() as f64 / trie_elapsed.as_nanos().max(1) as f64;
            println!(
                "n={:>6}  queries={}  hits={:>5}  linear={:>10?}  trie={:>10?}  speedup={:.1}x",
                n,
                queries.len(),
                hits_trie,
                linear_elapsed,
                trie_elapsed,
                speedup,
            );
        }
    }
}
