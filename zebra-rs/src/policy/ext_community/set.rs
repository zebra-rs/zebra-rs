use std::collections::BTreeSet;

use bgp_packet::BgpAttr;

use super::{ExtCommunityMatcher, match_ext_community_set};

#[derive(Default, Clone, Debug, PartialEq)]
pub struct ExtCommunitySet {
    pub vals: BTreeSet<ExtCommunityMatcher>,
    pub delete: bool,
}

impl ExtCommunitySet {
    pub fn matches(&self, bgp_attr: &BgpAttr) -> bool {
        self.vals
            .iter()
            .any(|m| match_ext_community_set(m, bgp_attr))
    }
}
