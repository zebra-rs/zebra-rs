use std::collections::BTreeSet;

use bgp_packet::BgpAttr;

use super::{AsPathMatcher, match_as_path_set};

#[derive(Default, Clone, Debug, PartialEq)]
pub struct AsPathSet {
    pub vals: BTreeSet<AsPathMatcher>,
    pub delete: bool,
}

impl AsPathSet {
    pub fn matches(&self, bgp_attr: &BgpAttr) -> bool {
        self.vals.iter().any(|x| match_as_path_set(x, bgp_attr))
    }
}
