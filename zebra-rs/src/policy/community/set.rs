// CommunitySet

use std::collections::BTreeSet;

use bgp_packet::BgpAttr;

use super::{CommunityMatcher, match_community_set};

#[derive(Default)]
pub struct CommunitySet {
    pub vals: BTreeSet<CommunityMatcher>,
    pub delete: bool,
}

impl CommunitySet {
    pub fn matches(&self, bgp_attr: &BgpAttr) -> bool {
        self.vals.iter().any(|x| match_community_set(x, bgp_attr))
    }
}
