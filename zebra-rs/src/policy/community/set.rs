// CommunitySet

use bgp_packet::BgpAttr;

use super::{CommunityMatcher, match_community_set};

pub struct CommunitySet {
    pub vals: Vec<CommunityMatcher>,
    pub delete: bool,
}

impl CommunitySet {
    pub fn matches(&self, bgp_attr: &BgpAttr) -> bool {
        self.vals.iter().any(|x| match_community_set(x, bgp_attr))
    }
}
