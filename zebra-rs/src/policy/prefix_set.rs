// Prefix set which may have IPv4 and IPv6 in a single set.
// Optional le, eq and ge option for prefixlen comparison.

use std::collections::BTreeSet;

use ipnet::IpNet;

#[derive(Default)]
pub struct PrefixSetEntry {
    pub entry: IpNet,
    pub le: Option<u8>,
    pub eq: Option<u8>,
    pub ge: Option<u8>,
}

#[derive(Default)]
pub struct PrefixSet {
    pub set: BTreeSet<PrefixSetEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init() {
        let mut pset = PrefixSet::default();
    }
}
