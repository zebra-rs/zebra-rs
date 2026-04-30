// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::BTreeMap;

use ipnet::IpNet;

#[derive(Default, Clone, Debug, PartialEq)]
pub struct PrefixSet {
    pub prefixes: BTreeMap<IpNet, PrefixSetEntry>,
    pub delete: bool,
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct PrefixSetEntry {
    pub le: Option<u8>,
    pub eq: Option<u8>,
    pub ge: Option<u8>,
}

impl PrefixSet {
    /// Check if the given IPv4 or IPv6 network matches any prefix in this set.
    ///
    /// A network matches if:
    /// 1. Its network address is contained within a prefix in the set
    /// 2. Its prefix length satisfies the filtering criteria (le, eq, ge) of that prefix
    pub fn matches(&self, net: impl Into<IpNet> + Copy) -> bool {
        let net_ip: IpNet = net.into();
        let prefix_len = net_ip.prefix_len();

        // Check each prefix in the set
        for (prefix, entry) in &self.prefixes {
            // Check if the network's IP is contained within this prefix
            if prefix.contains(&net_ip) {
                // Check prefix length constraints
                let mut matches = true;

                // Check less-than-or-equal constraint
                if let Some(le) = entry.le
                    && prefix_len > le
                {
                    matches = false;
                }

                // Check equal constraint
                if let Some(eq) = entry.eq
                    && prefix_len != eq
                {
                    matches = false;
                }

                // Check greater-than-or-equal constraint
                if let Some(ge) = entry.ge
                    && prefix_len < ge
                {
                    matches = false;
                }

                if matches {
                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_matches_ipv4_no_constraints() {
        let mut prefix_set = PrefixSet::default();
        let prefix = IpNet::from_str("10.0.0.0/8").unwrap();
        prefix_set
            .prefixes
            .insert(prefix, PrefixSetEntry::default());

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
        prefix_set.prefixes.insert(
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
        prefix_set.prefixes.insert(
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
        prefix_set.prefixes.insert(
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
        prefix_set.prefixes.insert(
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
        prefix_set.prefixes.insert(
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
        prefix_set.prefixes.insert(
            prefix1,
            PrefixSetEntry {
                le: Some(24),
                eq: None,
                ge: Some(16),
            },
        );

        // Add second prefix with different constraints
        let prefix2 = IpNet::from_str("192.168.0.0/16").unwrap();
        prefix_set.prefixes.insert(
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
        prefix_set
            .prefixes
            .insert(prefix, PrefixSetEntry::default());

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
}
