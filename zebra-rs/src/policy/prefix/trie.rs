use ipnet::IpNet;

/// Binary radix trie for IP prefixes.
///
/// Each path from the root spells out a prefix bit-by-bit (left = 0,
/// right = 1). A node with `stored = true` denotes that the prefix
/// terminating at that depth is a member of the set.
///
/// Addresses are normalized to MSB-aligned `u128`: an IPv4 address sits
/// in the top 32 bits, an IPv6 address fills all 128 bits. At depth
/// `d` (zero-indexed) the consulted bit is `(bits >> (127 - d)) & 1`.
#[derive(Default, Clone, Debug)]
pub struct PrefixTrie {
    root: Box<TrieNode>,
}

#[derive(Default, Clone, Debug)]
struct TrieNode {
    children: [Option<Box<TrieNode>>; 2],
    stored: bool,
}

impl TrieNode {
    fn is_dead(&self) -> bool {
        !self.stored && self.children[0].is_none() && self.children[1].is_none()
    }
}

impl PrefixTrie {
    pub fn insert(&mut self, bits: u128, len: u8) {
        let mut node = self.root.as_mut();
        for d in 0..len {
            let b = bit_at(bits, d) as usize;
            node = node.children[b].get_or_insert_with(Box::<TrieNode>::default);
        }
        node.stored = true;
    }

    pub fn remove(&mut self, bits: u128, len: u8) {
        remove_rec(&mut self.root, bits, len, 0);
    }

    /// Walk the trie along the path described by `bits`/`len`. Whenever
    /// a stored node is encountered (including depth 0 for a `/0` and
    /// depth `len` for an exact match), invoke `callback(depth)`. If
    /// the callback returns `true`, the walk stops.
    pub fn walk_enclosing<F>(&self, bits: u128, len: u8, mut callback: F)
    where
        F: FnMut(u8) -> bool,
    {
        let mut node = self.root.as_ref();
        for d in 0..=len {
            if node.stored && callback(d) {
                return;
            }
            if d == len {
                break;
            }
            let b = bit_at(bits, d) as usize;
            match node.children[b].as_deref() {
                Some(child) => node = child,
                None => return,
            }
        }
    }
}

fn remove_rec(node: &mut Box<TrieNode>, bits: u128, len: u8, depth: u8) -> bool {
    if depth == len {
        node.stored = false;
    } else {
        let b = bit_at(bits, depth) as usize;
        if let Some(child) = node.children[b].as_mut()
            && remove_rec(child, bits, len, depth + 1)
        {
            node.children[b] = None;
        }
    }
    node.is_dead()
}

#[inline]
fn bit_at(bits: u128, depth: u8) -> u8 {
    ((bits >> (127 - depth)) & 1) as u8
}

/// Convert an `IpNet` to (MSB-aligned bits, prefix length) and the
/// family flag (`true` for IPv4).
pub fn ipnet_to_bits(net: IpNet) -> (u128, u8, bool) {
    match net {
        IpNet::V4(n) => ((u32::from(n.network()) as u128) << 96, n.prefix_len(), true),
        IpNet::V6(n) => (u128::from(n.network()), n.prefix_len(), false),
    }
}

/// Build the IpNet that corresponds to taking the first `depth` bits
/// from the given query network.
pub fn truncate_prefix(net: IpNet, depth: u8) -> IpNet {
    match net {
        IpNet::V4(n) => ipnet::Ipv4Net::new(n.network(), depth)
            .expect("depth <= 32 for v4")
            .trunc()
            .into(),
        IpNet::V6(n) => ipnet::Ipv6Net::new(n.network(), depth)
            .expect("depth <= 128 for v6")
            .trunc()
            .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn bits_of(net_str: &str) -> (u128, u8) {
        let net = IpNet::from_str(net_str).unwrap();
        let (b, l, _) = ipnet_to_bits(net);
        (b, l)
    }

    #[test]
    fn insert_and_walk_v4() {
        let mut trie = PrefixTrie::default();
        let (b, l) = bits_of("10.0.0.0/8");
        trie.insert(b, l);

        let (q, ql) = bits_of("10.1.2.0/24");
        let mut hits = vec![];
        trie.walk_enclosing(q, ql, |d| {
            hits.push(d);
            false
        });
        assert_eq!(hits, vec![8]);
    }

    #[test]
    fn walk_collects_all_enclosing() {
        let mut trie = PrefixTrie::default();
        for p in &["0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"] {
            let (b, l) = bits_of(p);
            trie.insert(b, l);
        }
        let (q, ql) = bits_of("10.1.2.128/25");
        let mut hits = vec![];
        trie.walk_enclosing(q, ql, |d| {
            hits.push(d);
            false
        });
        assert_eq!(hits, vec![0, 8, 16, 24]);
    }

    #[test]
    fn walk_short_circuits() {
        let mut trie = PrefixTrie::default();
        for p in &["0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16"] {
            let (b, l) = bits_of(p);
            trie.insert(b, l);
        }
        let (q, ql) = bits_of("10.1.2.0/24");
        let mut hits = vec![];
        trie.walk_enclosing(q, ql, |d| {
            hits.push(d);
            d >= 8
        });
        assert_eq!(hits, vec![0, 8]);
    }

    #[test]
    fn remove_clears_marker_and_trims() {
        let mut trie = PrefixTrie::default();
        let (b, l) = bits_of("10.1.0.0/16");
        trie.insert(b, l);
        trie.remove(b, l);

        let (q, ql) = bits_of("10.1.2.0/24");
        let mut hits = 0;
        trie.walk_enclosing(q, ql, |_| {
            hits += 1;
            false
        });
        assert_eq!(hits, 0);
    }

    #[test]
    fn remove_keeps_other_branches() {
        let mut trie = PrefixTrie::default();
        for p in &["10.0.0.0/8", "10.1.0.0/16"] {
            let (b, l) = bits_of(p);
            trie.insert(b, l);
        }
        let (b, l) = bits_of("10.1.0.0/16");
        trie.remove(b, l);

        let (q, ql) = bits_of("10.1.2.0/24");
        let mut hits = vec![];
        trie.walk_enclosing(q, ql, |d| {
            hits.push(d);
            false
        });
        assert_eq!(hits, vec![8]);
    }

    #[test]
    fn ipv6_walk() {
        let mut trie = PrefixTrie::default();
        for p in &["2001:db8::/32", "2001:db8:1::/48"] {
            let net = IpNet::from_str(p).unwrap();
            let (b, l, _) = ipnet_to_bits(net);
            trie.insert(b, l);
        }
        let net = IpNet::from_str("2001:db8:1:2::/64").unwrap();
        let (q, ql, _) = ipnet_to_bits(net);
        let mut hits = vec![];
        trie.walk_enclosing(q, ql, |d| {
            hits.push(d);
            false
        });
        assert_eq!(hits, vec![32, 48]);
    }

    #[test]
    fn root_zero_prefix_matches_all() {
        let mut trie = PrefixTrie::default();
        let (b, l) = bits_of("0.0.0.0/0");
        trie.insert(b, l);
        let (q, ql) = bits_of("192.168.1.0/24");
        let mut hits = vec![];
        trie.walk_enclosing(q, ql, |d| {
            hits.push(d);
            false
        });
        assert_eq!(hits, vec![0]);
    }

    #[test]
    fn truncate_v4_and_v6() {
        let q = IpNet::from_str("10.1.2.128/25").unwrap();
        assert_eq!(
            truncate_prefix(q, 8),
            IpNet::from_str("10.0.0.0/8").unwrap()
        );
        assert_eq!(
            truncate_prefix(q, 24),
            IpNet::from_str("10.1.2.0/24").unwrap()
        );

        let q = IpNet::from_str("2001:db8:1:2::/64").unwrap();
        assert_eq!(
            truncate_prefix(q, 32),
            IpNet::from_str("2001:db8::/32").unwrap()
        );
    }
}
