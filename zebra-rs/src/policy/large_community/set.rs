use std::collections::BTreeSet;

use bgp_packet::BgpAttr;

use super::{LargeCommunityMatcher, match_large_community_set};

#[derive(Default, Clone, Debug, PartialEq)]
pub struct LargeCommunitySet {
    pub vals: BTreeSet<LargeCommunityMatcher>,
    pub delete: bool,
}

impl LargeCommunitySet {
    pub fn matches(&self, bgp_attr: &BgpAttr) -> bool {
        self.vals
            .iter()
            .any(|m| match_large_community_set(m, bgp_attr))
    }
}
