use std::collections::BTreeMap;

use ipnet::Ipv4Net;
use ospf_packet::ExtPrefixSubTlv;

#[derive(Default)]
pub struct ReachMap {
    map: BTreeMap<Ipv4Net, Vec<ExtPrefixSubTlv>>,
}

impl ReachMap {
    pub fn insert(
        &mut self,
        key: Ipv4Net,
        value: Vec<ExtPrefixSubTlv>,
    ) -> Option<Vec<ExtPrefixSubTlv>> {
        self.map.insert(key, value)
    }
}
